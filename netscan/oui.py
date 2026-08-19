"""MAC address -> hardware vendor lookup.

Ships with a curated table of prefixes common on home and office networks.
For authoritative coverage, run `netscan --update-oui`, which caches the IEEE
registry in ~/.netscan/oui.txt and is used automatically once present.
"""
from __future__ import annotations

import os
import re
from typing import Dict, Optional

CACHE_DIR = os.path.expanduser("~/.netscan")
CACHE_FILE = os.path.join(CACHE_DIR, "oui.txt")
IEEE_URL = "https://standards-oui.ieee.org/oui/oui.csv"

# Curated OUI prefixes (uppercase, no separators).
CURATED: Dict[str, str] = {}


def _add(vendor: str, *prefixes: str) -> None:
    for p in prefixes:
        key = re.sub(r"[^0-9A-Fa-f]", "", p).upper()[:6]
        if len(key) == 6:
            CURATED[key] = vendor


_add("Apple",
     "0003 93", "000A27", "000A95", "000D93", "0016CB", "0017F2", "0019E3", "001B63",
     "001EC2", "001F5B", "001FF3", "0021E9", "002241", "002312", "0023DF", "002500",
     "00254B", "0025BC", "002608", "00264A", "0026B0", "0026BB", "003065", "003EE1",
     "0050E4", "0056CD", "006171", "0088 65", "00A040", "00C610", "00CDFE", "00DB70",
     "00F4B9", "00F76F", "040CCE", "041552", "041E64", "042665", "04489A", "044BED",
     "0452F3", "045453", "0469F8", "04D3CF", "04DB56", "04E536", "04F13E", "04F7E4",
     "080007", "086698", "086D41", "087045", "087402", "0C1539", "0C3021", "0C3E9F",
     "0C4DE9", "0C5101", "0C74C2", "0C771A", "0CBC9F", "0CD746", "101C0C", "1040F3",
     "10417F", "1093E9", "109ADD", "10DDB1", "14109F", "145A05", "148FC6", "1499E2",
     "14BD61", "182032", "183451", "186590", "18810E", "189EFC", "18AF61", "18AF8F",
     "18E7F4", "18EE69", "18F1D8", "1C1AC0", "1C36BB", "1C5CF2", "1C9E46", "1CABA7",
     "1CE62B", "203CAE", "2078F0", "207D74", "209BCD", "20A2E4", "20AB37", "20C9D0",
     "241EEB", "24240E", "245BA7", "24A074", "24A2E1", "24AB81", "24E314", "24F094",
     "24F677", "280B5C", "283737", "285AEB", "286AB8", "286ABA", "28CFDA", "28CFE9",
     "28E02C", "28E14C", "28E7CF", "28F076", "2C1F23", "2C200B", "2C3361", "2CB43A",
     "2CBE08", "2CF0A2", "2CF0EE", "3010E4", "3035AD", "30636B", "3090AB", "30F7C5",
     "3408BC", "341298", "34159E", "34363B", "3451C9", "34A395", "34AB37", "34C059",
     "34E2FD", "380F4A", "38484C", "3871DE", "38B54D", "38C986", "38CADA", "3C0754",
     "3C15C2", "3C2EF9", "3CAB8E", "3CD0F8", "3CE072", "403004", "40331A", "403CFC",
     "406C8F", "4098AD", "409C28", "40A6D9", "40B395", "40D32D", "440010", "442A60",
     "444C0C", "44D884", "44FB42", "48437C", "4860BC", "48746E", "48A195", "48BF6B",
     "48D705", "4C3275", "4C57CA", "4C7C5F", "4C8D79", "4CB199", "503237", "507A55",
     "50EAD6", "542696", "5433CB", "544E90", "54724F", "54AE27", "54E43A", "54EAA8",
     "581FAA", "58404E", "5855CA", "587F57", "58B035", "5C5948", "5C8D4E", "5C95AE",
     "5C969D", "5CF5DA", "5CF7E6", "5CF938", "600308", "60334B", "606944", "608B0E",
     "609217", "60C547", "60D9C7", "60F445", "60F81D", "60FACD", "60FB42", "60FEC5",
     "64200C", "6476BA", "649ABE", "64A3CB", "64B0A6", "64B9E8", "64E682", "680927",
     "685B35", "68644B", "68967B", "689C70", "68A86D", "68AB1E", "68AE20", "68D93C",
     "68DBCA", "68FB7E", "6C19C0", "6C3E6D", "6C4008", "6C709F", "6C72E7", "6C8DC1",
     "6C94F8", "6C96CF", "6CAB31", "701124", "7014A6", "703EAC", "70480F", "705681",
     "7073CB", "7081EB", "70A2B3", "70CD60", "70DEE2", "70E72C", "70ECE4", "70F087",
     "741BB2", "748114", "748D08", "74E1B6", "74E2F5", "7831C1", "78321B", "783A84",
     "784F43", "7867D7", "786C1C", "787B8A", "78886D", "789F70", "78A3E4", "78CA39",
     "78D75F", "78FD94", "7C0191", "7C04D0", "7C11BE", "7C6D62", "7C6DF8", "7CC3A1",
     "7CC537", "7CD1C3", "7CF05F", "7CFADF", "80006E", "804971", "80929F", "80B03D",
     "80BE05", "80D605", "80E650", "80EA96", "80ED2C", "842999", "843835", "84788B",
     "848506", "8489AD", "848E0C", "84A134", "84B153", "84FCAC", "84FCFE", "881FA1",
     "885395", "8863DF", "8866A5", "88C663", "88CB87", "88E87F", "8C006D", "8C2937",
     "8C2DAA", "8C5877", "8C7B9D", "8C7C92", "8C8EF2", "8CFABA", "9027E4", "903C92",
     "9060F1", "907240", "90840D", "908D6C", "90B0ED", "90B21F", "90C1C6", "90FD61",
     "949426", "94BF2D", "94E96A", "94F6A3", "9800C6", "9801A7", "9803D8", "985AEB",
     "989E63", "98B8E3", "98D6BB", "98E0D9", "98F0AB", "98FE94", "9C04EB", "9C207B",
     "9C293F", "9C35EB", "9C4FDA", "9C760E", "9C84BF", "9C8BA0", "9CE33F", "9CF387",
     "9CF48E", "A01828", "A03BE3", "A04EA7", "A056F3", "A0999B", "A0D795", "A0EDCD",
     "A45E60", "A46706", "A4B197", "A4B805", "A4C361", "A4D18C", "A4D1D2", "A4F1E8",
     "A82066", "A85B78", "A85C2C", "A8667F", "A886DD", "A88808", "A88E24", "A8968A",
     "A8BBCF", "A8FAD8", "AC1F74", "AC293A", "AC3C0B", "AC61EA", "AC7F3E", "AC87A3",
     "ACBC32", "ACCF5C", "ACE4B5", "ACFDEC", "B03495", "B065BD", "B09FBA", "B0CA68",
     "B418D1", "B4F0AB", "B4F61C", "B8098A", "B817C2", "B841A4", "B844D9", "B853AC",
     "B8634D", "B8782E", "B88D12", "B8C111", "B8C75D", "B8E856", "B8F6B1", "B8FF61",
     "BC3BAF", "BC4CC4", "BC52B7", "BC5436", "BC6778", "BC6C21", "BC926B", "BC9FEF",
     "BCA920", "BCEC5D", "C06394", "C0847A", "C09F42", "C0A53E", "C0CCF8", "C0CECD",
     "C0D012", "C42C03", "C4B301", "C81EE7", "C82A14", "C8334B", "C83C85", "C869CD",
     "C86F1D", "C88550", "C8B5B7", "C8BCC8", "C8D083", "C8E0EB", "C8F650", "CC088D",
     "CC08E0", "CC20E8", "CC25EF", "CC29F5", "CC4463", "CC785F", "CCC760", "D0034B",
     "D023DB", "D02598", "D03311", "D04F7E", "D0817A", "D0A637", "D0C5F3", "D0D2B0",
     "D0E140", "D4619D", "D49A20", "D4A33D", "D4DCCD", "D4F46F", "D8004D", "D81D72",
     "D83062", "D89695", "D89E3F", "D8A25E", "D8BB2C", "D8CF9C", "D8D1CB", "DC0C5C",
     "DC2B2A", "DC2B61", "DC3714", "DC415F", "DC56E7", "DC86D8", "DC9B9C", "DCA4CA",
     "DCA904", "DCD3A2", "E05F45", "E0ACCB", "E0B52D", "E0B9BA", "E0C767", "E0C97A",
     "E0F5C6", "E0F847", "E425E7", "E42B34", "E48B7F", "E49A79", "E4C63D", "E4CE8F",
     "E4E4AB", "E8040B", "E80688", "E8802E", "E88D28", "E8B2AC", "EC3586", "EC852F",
     "ECADB8", "F01898", "F02475", "F07960", "F0989D", "F099BF", "F0B0E7", "F0B479",
     "F0C1F1", "F0CBA1", "F0D1A9", "F0DBE2", "F0DBF8", "F0DCE2", "F0F61C", "F40F24",
     "F41BA1", "F431C3", "F437B7", "F45C89", "F4F15A", "F4F951", "F80377", "F81EDF",
     "F82793", "F84D89", "F86214", "F86FC1", "F895C7", "FC253F", "FCD848", "FCE998",
     "FCFC48")

_add("Cisco", "00000C", "000142", "000A41", "000E38", "001A2F", "001BD4", "001EBE",
     "002497", "00260A", "2C3F38", "3C5EC3", "4C4E35", "5897BD", "6C2056", "700B4F",
     "78BC1A", "885A92", "A0ECF9", "B41489", "C4B36A", "E0D173", "F40F1B", "0007EB")
_add("Cisco Meraki", "00180A", "881544", "E0CBBC", "3456FE", "AC17C8", "0C8DDB", "981888")
_add("Ubiquiti", "0418D6", "245A4C", "44D9E7", "687251", "7483C2", "788A20", "802AA8",
     "DC9FDB", "F09FC2", "FCECDA", "18E829", "74ACB9", "9C05D6", "B4FBE4", "E063DA",
     "24A43C", "68D79A", "802AA8", "F492BF", "70A741", "E438 83")
_add("TP-Link", "001D0F", "14CC20", "50C7BF", "60E327", "6466B3", "98DAC4", "A42BB0",
     "AC84C6", "B04E26", "C006C3", "C4E984", "E8DE27", "EC086B", "F4F26D", "30DE4B",
     "003192", "5CA6E6", "9C5322", "D807B6", "1027F5", "3C52A1", "540EE1")
_add("Netgear", "00095B", "000FB5", "00146C", "001B2F", "001E2A", "00223F", "0024B2",
     "0026F2", "08028E", "204E7F", "28C68E", "2C3033", "30469A", "4494FC", "6CB0CE",
     "841B5E", "9C3DCF", "A00460", "A040A0", "C03F0E", "C40415", "DCEF09", "E0469A",
     "E091F5", "E4F4C6")
_add("ASUS", "000C6E", "00112F", "0013D4", "001731", "001BFC", "001E8C", "002215",
     "00248C", "0026 18", "049226", "08606E", "0C9D92", "10BF48", "14DDA9", "1C872C",
     "20CF30", "2C4D54", "305A3A", "3085A9", "38D547", "40167E", "484D7E", "50465D",
     "540969", "6045CB", "704D7B", "74D02B", "7824AF", "88D7F6", "9C5C8E", "AC220B",
     "B06EBF", "BCAEC5", "C86000", "D017C2", "D850E6", "E03F49", "F832E4", "FCC233")
_add("D-Link", "00055D", "000D88", "000F3D", "001195", "0015E9", "00179A", "001B11",
     "001CF0", "001E58", "002191", "0022B0", "0024 01", "1CBDB9", "28107B", "340804",
     "3C1E04", "5CD998", "78542E", "84C9B2", "902B34", "B8A386", "C8BE19", "CCB255",
     "F07D68", "FC7516")
_add("Linksys", "000625", "000C41", "000E08", "0012 17", "0013 10", "001839", "001A70",
     "001C10", "001D7E", "001EE5", "0021 29", "002369", "0025 9C", "141BBD", "20AA4B",
     "48F8B3", "586D8F", "60383E", "687F74", "C0C1C0", "C8D719")
_add("Espressif (ESP IoT)",
     "18FE34", "240AC4", "24B2DE", "2C3AE8", "30AEA4", "3C71BF", "5CCF7F", "600194",
     "68C63A", "7C9EBD", "840D8E", "84CCA8", "84F3EB", "8CAAB5", "9097D5", "A020A6",
     "A47B9D", "A4CF12", "ACD074", "B4E62D", "BCDDC2", "C44F33", "CC50E3", "D8A01D",
     "D8BFC0", "DC4F22", "E09806", "ECFABC", "F008D1", "F4CFA2", "FCF5C4", "246F28",
     "30C6F7", "34865D", "4022D8", "483FDA", "4C11AE", "5443B2", "58BF25", "7CDFA1",
     "8C4B14", "94B555", "94B97E", "A848FA", "C8C9A3", "CCDBA7", "D4D4DA", "E89F6D",
     "EC64C9", "F412FA")
_add("Raspberry Pi", "B827EB", "DCA632", "E45F01", "28CDC1", "D83ADD", "2CCF67")
_add("Samsung", "0012FB", "001599", "001632", "001A8A", "002119", "002339", "002454",
     "0808C2", "08373D", "0C1420", "101DC0", "1449E0", "183A2D", "1C5A3E", "2013E0",
     "244B81", "28395E", "2CAE2B", "301966", "3423BA", "34BE00", "38AA3C", "3C8BFE",
     "400E85", "444E1A", "4C3C16", "503275", "54880E", "5C0A5B", "5CF6DC", "606BBD",
     "64B853", "68EBAE", "6C2F2C", "70F927", "781FDB", "7CF854", "8425DB", "88329B",
     "8C71F8", "90187C", "94350A", "9852B1", "9C0298", "A02195", "A4EBD3", "A8F274",
     "AC5F3E", "B072BF", "B407F9", "B85E7B", "BC1485", "BC20A4", "C0BDD1", "C4731E",
     "C819F7", "CC07AB", "D022BE", "D487D8", "D857EF", "DC44B6", "E4121D", "E8508B",
     "EC1F72", "F05A09", "F40E22", "F8042E", "FC0012", "FC8F90")
_add("Amazon", "007147", "0847C9"[:6], "0C47C9", "10AE60", "18742E", "1C12B0", "34D270",
     "38F73D", "40B4CD", "440049", "44650D", "4CEFC0", "50DCE7", "50F5DA", "6837E9",
     "6854FD", "6C5697", "747548", "74C246", "78E103", "8871E5", "A002DC", "AC63BE",
     "B047BF", "B0FC0D", "C86C3D", "CC9EA2", "F0272D", "F08173", "FC65DE", "FCA183",
     "0CDCCC", "40A2DB", "84D6D0", "A8E621")
_add("Google / Nest", "001A11", "3C5AB4", "54600A", "6045BD", "94EB2C", "A47733",
     "D86C63", "F4F5D8", "F4F5E8", "F88FCA", "1CF29A", "20DF B9", "3872C0", "48D6D5",
     "6466B3"[:6], "7477 7C", "9457A5", "AC67 84", "DA A1 19", "E4F042", "F0EF86",
     "F8CFC5", "30FD38", "44070B", "5065F3"[:6])
_add("Sonos", "000E58", "347E5C", "48A6B8", "5CAAFD", "78 28 CA", "94 9F 3E", "B8E937",
     "F0F6C1", "542A1B")
_add("Roku", "008041"[:6], "0C1420"[:6], "10599D", "20EF BD", "88DEA9", "AC3A7A",
     "B0A737", "B83E59", "C83A6B", "CC6DA0", "D0 4D 2C", "DC3A5E")
_add("Sonoff / ITEAD", "600194"[:6], "A48 CDB"[:6], "DC4F22"[:6])
_add("Philips Hue", "001788", "ECB5FA")
_add("Intel", "001B21", "001E64", "0021 6A", "0022 FB", "0024D7", "3417EB", "34E12D",
     "3C970E", "44850 0"[:6], "48513 4"[:6], "5CE0C5", "606720", "6C8814", "7C7A91",
     "8C1645", "941882", "9421 97"[:6], "A0A8CD", "A4C494", "B4B686", "C82970"[:6],
     "D0577B", "D46D6D", "DC5360"[:6], "E4A471", "E8B1FC", "F8342 A"[:6], "FCF8AE",
     "00A0C9", "001517", "0013CE", "001320")
_add("Dell", "000874", "000BDB", "000D56", "0011 43", "0012 3F", "0013 72", "0014 22",
     "0015C5", "0018 8B", "0019B9", "001AA0", "001C23", "001D09", "001E4F", "001EC9",
     "0021 70", "0021 9B", "002219", "0023AE", "00248C"[:6], "0026B9", "14B31F",
     "180373", "1866DA", "20040F", "246E96", "34172 4"[:6], "5448 10"[:6], "782BCB",
     "84 7B EB", "B083FE", "B885 84"[:6], "D067E5", "F04DA2", "F48E38", "F8BC12",
     "F8CA B8")
_add("HP / HPE", "0001E6", "000883", "000A57", "000E7F", "000F20", "0010 83", "001279",
     "0014 38", "0016 35", "001708", "0018FE", "001A4B", "001B78", "001CC4", "001E0B",
     "001F29", "0021 5A", "0023 7D", "002481", "00256 0"[:6], "0026 55", "0030 6E",
     "10604B", "1CC1DE", "2C4138", "2C59E5", "302432", "308D99", "3822 D6"[:6],
     "3C4A92", "3CD92B", "441EA1", "5065F3", "6CC217", "70106F", "705A0F", "78ACC0",
     "80C16E", "8851FB", "94185 7"[:6], "9C8E99", "A0481C", "A0D3C1", "B05ADA",
     "C8CBB8", "D07E28", "D89D67", "DC4A3E", "E4115B", "EC8EB5", "F0921C", "FC15B4")
_add("Synology", "0011 32", "001132", "0C74C2"[:6], "90 09 D0", "9009D0")
_add("QNAP", "00089B", "245EBE", "00 08 9B")
_add("Western Digital", "00 90 A9", "0090A9", "0014EE", "0018 71"[:6], "9C4E36"[:6])
_add("Sophos", "000C29"[:6], "1CE85D")
_add("VMware (virtual)", "000569", "000C29", "001C14", "005056", "080027"[:6])
_add("VirtualBox (virtual)", "080027", "0A0027")
_add("Parallels (virtual)", "001C42")
_add("QEMU/KVM (virtual)", "525400")
_add("Microsoft / Xbox", "0003FF", "000D3A", "0012 5A", "0015 5D", "001DD8", "0022 48",
     "0025AE", "0050F2", "281878", "3C8375", "485073"[:6], "5CBA37", "6045BD"[:6],
     "7C1E52", "7CED8D", "984FEE", "B4AE2B", "C4 9D ED", "D8B12A", "DC98 40"[:6],
     "F01DBC", "0017FA", "58 82 A8", "9C AA 1B", "0C2A69"[:6])
_add("Sony", "0001 4A", "00013 A"[:6], "0004 1F", "000AD9", "000EA6"[:6], "0013A9",
     "0015C1", "0016 20"[:6], "0019C5", "001A80", "001B59", "001CA4", "001D0D",
     "001DBA", "001EDC", "0021 9E", "0024BE", "0025E7", "30F9ED", "3C0771", "544249",
     "5CB524", "78843C", "8400D2", "AC9B0A", "B4527D", "BC6E64", "D8D43C", "FC0FE6")
_add("LG Electronics", "0005C9", "000E2E"[:6], "0012 47", "001C62", "001E75", "001F6B",
     "0021FB", "0022A9", "0024 83", "0025E5", "00E091", "10683F", "2021A5", "2C598A",
     "343111", "3CBDD8", "40B0FA", "48597 9"[:6], "58A2B5", "60E3AC"[:6], "6CDD BC",
     "700514", "78 5D C8", "88C9D0", "98D6F7", "A039F7", "A816B2", "AC0D1B", "B81DAA",
     "C4366C", "CC2D8C", "DC0B34", "E85B5B", "F80CF3")
_add("Xiaomi", "0C1DAF", "102AB3", "141F78", "185936", "204747", "286C07", "28E31F",
     "34CE00", "3C BD 3E", "482CA0", "4C49E3", "50 8F 4C", "5CC308"[:6], "640980",
     "685E6B", "6C 5A B5"[:6], "748F3C"[:6], "78 11 DC", "7C1DD9", "8C BE BE",
     "9C 99 A0", "A086C6"[:6], "AC C1 EE", "B0E235", "C46AB7", "D4970B", "E8AB FA",
     "F0B429", "F48B32", "FC64BA")
_add("Huawei", "001882", "0018 4A"[:6], "00259E", "002EC7", "0446 65"[:6], "086361",
     "0C37DC", "10 47 80", "1C1D67", "20F3A3", "240995", "283152", "2C55D3"[:6],
     "308730", "3CDFBD", "4025C2"[:6], "48435A", "4C5499"[:6], "5442 49"[:6],
     "5CB395"[:6], "643E8C", "70723C", "781DBA", "80717A", "84A8E4", "88E3AB",
     "9C28EF", "A0F479"[:6], "AC4E91", "B41513"[:6], "C40528"[:6], "CC53B5", "D0D04B",
     "E0247F"[:6], "E8088B", "F49FF3")
_add("Brother (printer)", "0080 77", "008077", "3C2AF4", "008092"[:6])
_add("Canon (printer)", "0000 85", "000085", "001E8F", "2400BA", "88 87 17"[:6])
_add("Epson (printer)", "000048", "001B A9", "38 1A 52"[:6], "44D244", "9C 5A 44"[:6],
     "A4 EE 57"[:6], "E8 9E B4"[:6], "001BA9")
_add("Zebra (printer)", "0007 4D", "00074D", "0015 70"[:6], "AC3FA4")
_add("Axis (camera)", "00408C", "ACCC8E", "B8A44F", "E82725")
_add("Hikvision (camera)", "0011 3F"[:6], "18 68 CB", "1C1B68"[:6], "2841 EC"[:6],
     "44 19 B6", "4C BD 8F"[:6], "54C4 15"[:6], "58 03 FB"[:6], "8C E7 48"[:6],
     "A4 14 37", "BC AD 28", "C0 56 E3", "E0CA3C"[:6], "F84DFC"[:6])
_add("Dahua (camera)", "3C EF 8C"[:6], "4C11BF", "90 02 A9", "9C 14 63"[:6], "A0BD1D",
     "BC325F", "E0 50 8B"[:6], "E4 24 6C"[:6])
_add("Wyze (camera)", "2C AA 8E", "7C 78 B2", "A4DA22", "D03F27")
_add("Ring / Amazon devices", "0C4762"[:6], "5CF3 70"[:6], "9C 76 13"[:6])
_add("Tesla", "4CFCAA", "98ED5C", "CC88 26"[:6], "F4 4E FD"[:6])
_add("Nintendo", "0009BF", "001656", "001AE9", "001BEA", "001CBE", "001DBC", "001E35",
     "001FC5", "0021BD", "00224C", "002331", "0025A0", "0026 59", "182A7B", "2C10C1",
     "34AF2C", "40D28A", "58BDA3", "5C521E", "606BFF", "78A2A0", "8CCDE8", "98B6E9",
     "9CE635", "A45C27", "B88AEC", "CC9E00", "E00C7F", "E84ECE")
_add("Nvidia", "00044B", "001955", "0416 7F"[:6], "48B02D")
_add("Lenovo", "0012FE"[:6], "1C69 7A"[:6], "50 7B 9D"[:6], "6C0B84"[:6], "8C1645"[:6],
     "A4 8C DB"[:6], "C85B76", "E8 6A 64"[:6])
_add("Realtek", "00E04C", "525400"[:6], "9C 5A 44"[:6])
_add("Broadcom", "001018", "00 10 18")
_add("MikroTik", "0000 00"[:0] or "4C5E0C", "6C3B6B", "744D28", "B869F4", "CC2DE0",
     "D401C3", "DC2C6E", "E48D8C", "18FD74", "2CC81B", "48A98A", "64D154", "78 9A 18")
_add("Aruba / HPE Networking", "000B86", "18 64 72", "20A6CD", "24DEC6", "6CF37F",
     "84D47E", "94B40F", "9C1C12", "AC A3 1E", "D8C7C8", "F0 5C 19")
_add("Fortinet", "000944", "085B0E", "0C 8D DB"[:6], "708B CD", "90 6C AC", "E0 23 FF")
_add("Sagemcom / ISP router", "0019 70"[:6], "1062 EB"[:6], "3872 C0"[:6], "70 5A 9E",
     "8C 5A 25"[:6], "C0 05 C2"[:6], "F0 84 2F")
_add("Technicolor / ISP router", "0014 7F"[:6], "3872C0"[:6], "44 32 C8", "7C 03 4C",
     "A4 B1 E9", "C4 EA 1D", "F8 6B D9")
_add("Arris / CommScope", "000039"[:6], "0015 96"[:6], "0026 42"[:6], "3C 7A 8A",
     "40 70 09", "5C 57 1A", "94 CC B9", "A0 8E 78", "BC 64 4B", "D4 04 CD", "F8 7B 20")
_add("Belkin / Wemo", "001CDF", "08 86 3B", "94 10 3E", "B4750E", "C05627", "EC1A59")
_add("Tuya / Smart Life", "10 D5 61"[:6], "18 69 D0"[:6], "50 02 91"[:6], "68 57 2D",
     "84 E3 42", "D4 A6 51"[:6], "DC 4F 22"[:6])
_add("Shelly / Allterco", "3494 54"[:6], "8CAAB5"[:6], "B0 B2 1C", "E8 68 E7")
_add("Honeywell", "00 D0 2D"[:6], "B8 2C A0", "EC 71 DB"[:6])
_add("Bose", "00 0C 8A", "04 A3 16", "2C 41 A1", "38 18 4C", "60 12 8B", "70 88 6B",
     "AC BB 61", "C8 DF 84")
_add("Chamberlain / MyQ", "64 52 99", "88 4A EA"[:6])
_add("Ecobee", "44 61 32")
_add("Roomba / iRobot", "50 14 79", "C0 7C 3D"[:6])

# Locally-administered bit (second-least-significant bit of first octet).
def is_locally_administered(mac: str) -> bool:
    try:
        first = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    return bool(first & 0x02)


def is_multicast(mac: str) -> bool:
    try:
        return bool(int(mac.split(":")[0], 16) & 0x01)
    except (ValueError, IndexError):
        return False


def normalize(mac: str) -> str:
    """macOS arp prints '0:1c:42:5c:6a:48' — pad each octet to two hex digits."""
    parts = re.split(r"[:\-]", mac.strip())
    if len(parts) != 6:
        return mac.lower()
    try:
        return ":".join(f"{int(p, 16):02x}" for p in parts)
    except ValueError:
        return mac.lower()


_ieee_cache: Optional[Dict[str, str]] = None


def _load_ieee() -> Dict[str, str]:
    global _ieee_cache
    if _ieee_cache is not None:
        return _ieee_cache
    table: Dict[str, str] = {}
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    prefix, _, vendor = line.partition("\t")
                    if prefix and vendor:
                        table[prefix.strip().upper()] = vendor.strip()
        except OSError:
            pass
    _ieee_cache = table
    return table


def lookup(mac: Optional[str]) -> Optional[str]:
    """Return the vendor for a MAC address, or None."""
    if not mac:
        return None
    mac = normalize(mac)
    key = mac.replace(":", "").upper()[:6]
    ieee = _load_ieee()
    if key in ieee:
        return ieee[key]
    if key in CURATED:
        return CURATED[key]
    if is_locally_administered(mac):
        return "Randomised MAC (private address)"
    return None


def describe(mac: Optional[str]) -> Optional[str]:
    """Vendor plus a note about randomised addresses."""
    if not mac:
        return None
    vendor = lookup(mac)
    if vendor and vendor != "Randomised MAC (private address)" and is_locally_administered(mac):
        return f"{vendor} (randomised MAC)"
    return vendor


def update_from_ieee(timeout: float = 60.0) -> tuple:
    """Download the IEEE OUI registry into the local cache. Returns (ok, message)."""
    import csv
    import io
    import urllib.request

    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        req = urllib.request.Request(IEEE_URL, headers={"User-Agent": "netscan/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001 - surfaced to the user
        return False, f"Download failed: {exc}"

    rows = list(csv.DictReader(io.StringIO(raw)))
    if not rows:
        return False, "Downloaded file was empty or unparseable"

    tmp = CACHE_FILE + ".tmp"
    count = 0
    with open(tmp, "w", encoding="utf-8") as fh:
        for row in rows:
            prefix = (row.get("Assignment") or "").strip().upper()
            vendor = (row.get("Organization Name") or "").strip()
            if len(prefix) == 6 and vendor:
                fh.write(f"{prefix}\t{vendor}\n")
                count += 1
    os.replace(tmp, CACHE_FILE)
    global _ieee_cache
    _ieee_cache = None
    return True, f"Cached {count:,} vendor prefixes in {CACHE_FILE}"


def cache_status() -> Optional[str]:
    if not os.path.exists(CACHE_FILE):
        return None
    import time
    age_days = (time.time() - os.path.getmtime(CACHE_FILE)) / 86400
    return f"{len(_load_ieee()):,} IEEE prefixes (updated {age_days:.0f} days ago)"
