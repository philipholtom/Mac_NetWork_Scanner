// Draws the NetScan app icon at every size macOS needs and writes an .iconset.
// Everything is drawn natively at each size (rather than downscaled from one
// large bitmap) so the small variants stay crisp, and fine detail is dropped
// at 16-32px where it would turn to mush.
//
//   swiftc -O GenerateIcon.swift -o generate-icon && ./generate-icon <outdir>

import AppKit
import CoreGraphics
import Foundation

// MARK: - Geometry helpers

/// Apple-style squircle (superellipse) rather than a plain rounded rect.
func squirclePath(in rect: CGRect, exponent: CGFloat = 5.0) -> CGPath {
    let path = CGMutablePath()
    let a = rect.width / 2, b = rect.height / 2
    let cx = rect.midX, cy = rect.midY
    let steps = 720
    for i in 0...steps {
        let t = CGFloat(i) / CGFloat(steps) * 2 * .pi
        let ct = cos(t), st = sin(t)
        let x = cx + a * copysign(pow(abs(ct), 2 / exponent), ct)
        let y = cy + b * copysign(pow(abs(st), 2 / exponent), st)
        if i == 0 { path.move(to: CGPoint(x: x, y: y)) } else { path.addLine(to: CGPoint(x: x, y: y)) }
    }
    path.closeSubpath()
    return path
}

func rgb(_ r: CGFloat, _ g: CGFloat, _ b: CGFloat, _ a: CGFloat = 1) -> CGColor {
    CGColor(srgbRed: r / 255, green: g / 255, blue: b / 255, alpha: a)
}

// MARK: - The icon

func drawIcon(size: CGFloat, context ctx: CGContext) {
    let s = size                       // everything below is expressed in units of s
    let detail = s >= 128 ? 2 : (s >= 48 ? 1 : 0)

    ctx.setAllowsAntialiasing(true)
    ctx.interpolationQuality = .high

    // --- Bundle shape: inset slightly, as macOS icons do not fill the canvas.
    let inset = s * 0.094
    let bounds = CGRect(x: inset, y: inset, width: s - inset * 2, height: s - inset * 2)
    let shape = squirclePath(in: bounds)

    // Drop shadow beneath the tile (skipped at tiny sizes where it just smudges).
    if detail >= 1 {
        ctx.saveGState()
        ctx.setShadow(offset: CGSize(width: 0, height: -s * 0.012),
                      blur: s * 0.03,
                      color: rgb(0, 0, 0, 0.32))
        ctx.addPath(shape)
        ctx.setFillColor(rgb(20, 40, 90))
        ctx.fillPath()
        ctx.restoreGState()
    }

    ctx.saveGState()
    ctx.addPath(shape)
    ctx.clip()

    // --- Background gradient: bright blue at the top into deep navy.
    let space = CGColorSpaceCreateDeviceRGB()
    let background = CGGradient(colorsSpace: space,
                                colors: [rgb(86, 152, 255), rgb(34, 76, 198), rgb(7, 20, 68)] as CFArray,
                                locations: [0.0, 0.42, 1.0])!
    ctx.drawLinearGradient(background,
                           start: CGPoint(x: bounds.minX, y: bounds.maxY),
                           end: CGPoint(x: bounds.maxX, y: bounds.minY),
                           options: [])

    let center = CGPoint(x: bounds.midX, y: bounds.midY)
    let maxRadius = bounds.width * 0.40

    // --- Radar sweep: a wedge built from thin slices so it fades out smoothly.
    if detail >= 1 {
        let sweepStart: CGFloat = .pi * 0.08     // trailing edge
        let sweepSpan: CGFloat = .pi * 0.46      // how wide the sweep is
        // One antialiased wedge filled with a gradient running from its trailing
        // edge to its leading edge. Building the fade out of many thin slices
        // instead leaves faint banding where their edges meet.
        ctx.saveGState()
        ctx.move(to: center)
        ctx.addArc(center: center, radius: maxRadius * 1.02,
                   startAngle: sweepStart, endAngle: sweepStart + sweepSpan, clockwise: false)
        ctx.closePath()
        ctx.clip()
        let fadeRadius = maxRadius * 0.72
        let fade = CGGradient(colorsSpace: space,
                              colors: [rgb(150, 245, 255, 0.0),
                                       rgb(150, 245, 255, 0.42),
                                       rgb(180, 250, 255, 0.88)] as CFArray,
                              locations: [0.0, 0.55, 1.0])!
        ctx.drawLinearGradient(
            fade,
            start: CGPoint(x: center.x + cos(sweepStart) * fadeRadius,
                           y: center.y + sin(sweepStart) * fadeRadius),
            end: CGPoint(x: center.x + cos(sweepStart + sweepSpan) * fadeRadius,
                         y: center.y + sin(sweepStart + sweepSpan) * fadeRadius),
            options: [.drawsBeforeStartLocation, .drawsAfterEndLocation])
        ctx.restoreGState()

        // Bright leading edge of the sweep.
        let lead = sweepStart + sweepSpan
        ctx.setStrokeColor(rgb(190, 250, 255, 0.85))
        ctx.setLineWidth(max(1, s * 0.008))
        ctx.setLineCap(.round)
        ctx.move(to: center)
        ctx.addLine(to: CGPoint(x: center.x + cos(lead) * maxRadius,
                                y: center.y + sin(lead) * maxRadius))
        ctx.strokePath()
    }

    // --- Concentric range rings.
    let ringCount = detail >= 2 ? 3 : (detail >= 1 ? 2 : 1)
    ctx.setLineWidth(max(1, s * (detail == 0 ? 0.05 : 0.0135)))
    for i in 0..<ringCount {
        let r = maxRadius * (CGFloat(i + 1) / CGFloat(ringCount))
        ctx.setStrokeColor(rgb(190, 225, 255, 0.34 + 0.16 * CGFloat(i)))
        ctx.addArc(center: center, radius: r, startAngle: 0, endAngle: .pi * 2, clockwise: false)
        ctx.strokePath()
    }

    // --- Discovered devices sitting on the rings.
    // Normalised (angle, radiusFraction, isHighlighted).
    let nodes: [(CGFloat, CGFloat, Bool)] = [
        (.pi * 0.42, 0.99, true),      // just caught by the sweep
        (.pi * 1.18, 0.66, false),
        (.pi * 1.72, 1.00, false),
        (.pi * 0.86, 0.34, false),
    ]
    let visible = detail >= 2 ? nodes : (detail >= 1 ? Array(nodes.prefix(2)) : [])
    for (angle, radiusFraction, highlighted) in visible {
        let p = CGPoint(x: center.x + cos(angle) * maxRadius * radiusFraction,
                        y: center.y + sin(angle) * maxRadius * radiusFraction)
        let dot = s * (highlighted ? 0.043 : 0.032)
        if highlighted && detail >= 2 {
            ctx.setFillColor(rgb(150, 245, 255, 0.30))
            ctx.fillEllipse(in: CGRect(x: p.x - dot * 2.1, y: p.y - dot * 2.1,
                                       width: dot * 4.2, height: dot * 4.2))
        }
        ctx.setFillColor(highlighted ? rgb(170, 250, 255) : rgb(255, 255, 255, 0.92))
        ctx.fillEllipse(in: CGRect(x: p.x - dot, y: p.y - dot, width: dot * 2, height: dot * 2))
    }

    // --- This Mac, at the centre.
    let core = s * (detail == 0 ? 0.075 : 0.055)
    if detail >= 2 {
        ctx.setFillColor(rgb(255, 255, 255, 0.22))
        ctx.fillEllipse(in: CGRect(x: center.x - core * 2.0, y: center.y - core * 2.0,
                                   width: core * 4.0, height: core * 4.0))
    }
    ctx.setFillColor(rgb(255, 255, 255))
    ctx.fillEllipse(in: CGRect(x: center.x - core, y: center.y - core,
                               width: core * 2, height: core * 2))

    // --- Glossy highlight across the top for a little depth.
    if detail >= 1 {
        let gloss = CGGradient(colorsSpace: space,
                               colors: [rgb(255, 255, 255, 0.22), rgb(255, 255, 255, 0.0)] as CFArray,
                               locations: [0.0, 1.0])!
        ctx.drawLinearGradient(gloss,
                               start: CGPoint(x: bounds.midX, y: bounds.maxY),
                               end: CGPoint(x: bounds.midX, y: bounds.midY + bounds.height * 0.06),
                               options: [])
    }

    ctx.restoreGState()

    // --- Hairline edge so the tile reads against a light background.
    if detail >= 1 {
        ctx.addPath(shape)
        ctx.setStrokeColor(rgb(255, 255, 255, 0.16))
        ctx.setLineWidth(max(1, s * 0.005))
        ctx.strokePath()
    }
}

// MARK: - Output

func writePNG(size: Int, to url: URL) throws {
    let space = CGColorSpaceCreateDeviceRGB()
    guard let ctx = CGContext(data: nil, width: size, height: size, bitsPerComponent: 8,
                              bytesPerRow: 0, space: space,
                              bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else {
        throw NSError(domain: "icon", code: 1)
    }
    drawIcon(size: CGFloat(size), context: ctx)
    guard let image = ctx.makeImage() else { throw NSError(domain: "icon", code: 2) }
    let rep = NSBitmapImageRep(cgImage: image)
    guard let data = rep.representation(using: .png, properties: [:]) else {
        throw NSError(domain: "icon", code: 3)
    }
    try data.write(to: url)
}

let outputDirectory = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "."
let iconset = URL(fileURLWithPath: outputDirectory).appendingPathComponent("AppIcon.iconset")
try? FileManager.default.createDirectory(at: iconset, withIntermediateDirectories: true)

// (point size, scale) pairs macOS expects in an iconset.
let variants: [(Int, Int)] = [(16, 1), (16, 2), (32, 1), (32, 2), (128, 1), (128, 2),
                              (256, 1), (256, 2), (512, 1), (512, 2)]
for (points, scale) in variants {
    let pixels = points * scale
    let suffix = scale == 1 ? "" : "@2x"
    let name = "icon_\(points)x\(points)\(suffix).png"
    try writePNG(size: pixels, to: iconset.appendingPathComponent(name))
    print("  \(name)  (\(pixels)px)")
}
print("iconset written to \(iconset.path)")
