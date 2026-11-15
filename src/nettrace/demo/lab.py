"""The Acme Corp demo architecture. Single source of truth for the simulators, the demo inventory,
the topology layout shown in the web UI, and the preset scenarios.

    Prisma Access (mobile users 100.64.0.0/16, branch-12 10.50.12.0/24)
        │ service connection SC-US-East (Tunnel200)
    DC1 ── core-rtr1 (IOS-XE) ── fw-dc1 (PA-3420 HA pair, Panorama) ── Internet
            │ users 10.1.10.0/24   │ DMZ 10.1.30.0/24 (www01, DNAT 203.0.113.10)
            │ servers 10.1.20.0/24 │ tunnel.1 IPsec
                                   ▼
    AWS us-east-1   Transit Gateway (network account)
        ├─ inspection VPC 10.100.0.0/16 ── fw-aws-1 (VM-Series, Panorama) ── IGW
        ├─ prod VPC 10.20.0.0/16 (app-prod account): web01 10.20.1.50, db01 10.20.2.10
        └─ shared VPC 10.30.0.0/16 (shared-services account): dns01 10.30.1.53
    TGW route tables: spokes (0/0 -> inspection), inspection (routes back to spokes and on-prem)
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from typing import Any

REGION = "us-east-1"
AZ, AZ_ID = "us-east-1a", "use1-az1"
ACCT_NET, ACCT_PROD, ACCT_SHARED = "111122223333", "444455556666", "777788889999"


def rid(prefix: str, name: str, n: int = 17) -> str:
    """Deterministic AWS-style id, so ids are stable between runs and in screenshots."""
    return f"{prefix}-0{hashlib.sha1(name.encode(), usedforsecurity=False).hexdigest()[:n - 1]}"


# ==== Cisco IOS-XE ===================================================================
CISCO: dict[str, dict[str, Any]] = {
    "core-rtr1": {
        "hostname": "CORE-RTR1", "model": "C8300-1N1S-6T", "version": "17.12.4", "mgmt": "10.255.0.1",
        "interfaces": [
            {"name": "GigabitEthernet1", "ip": "10.0.0.1/30", "desc": "to fw-dc1 ethernet1/1"},
            {"name": "GigabitEthernet2", "ip": "10.1.10.1/24", "desc": "USERS vlan 10", "acl_in": "USERS-IN"},
            {"name": "GigabitEthernet3", "ip": "10.1.20.1/24", "desc": "SERVERS vlan 20", "acl_out": "SERVERS-OUT"},
            # "nat" / "zone" / "inspect" feed `show ip nat statistics` / `show zone security` /
            # `show ip inspect interfaces` in sim_cisco. Only the guest VLAN uses one, so the other presets keep
            # their outcome; nettrace does not evaluate NAT, so a flow from here is UNKNOWN (preset guest-nat).
            {"name": "GigabitEthernet4", "ip": "10.1.40.1/24", "desc": "GUEST vlan 40 (NAT inside)", "nat": "inside"},
            {"name": "Tunnel200", "ip": "169.254.200.2/30", "desc": "Prisma Access SC-US-East"},
            {"name": "Loopback0", "ip": "10.255.0.1/32", "desc": "router-id"},
        ],
        "routes": [  # prefix, next hop, interface, source
            ("0.0.0.0/0", "10.0.0.2", "GigabitEthernet1", "static"),
            ("100.64.0.0/16", "169.254.200.1", "Tunnel200", "bgp 65010"),
            ("10.50.0.0/16", "169.254.200.1", "Tunnel200", "bgp 65010"),
        ],
        "arp": {"10.1.10.25": "0050.56a1.0a19", "10.1.20.10": "0050.56a1.140a", "10.0.0.2": "b40c.25e0.0011",
                "10.1.20.11": "0050.56a1.140b"},
        "acls": {
            "USERS-IN": ["10 deny tcp any any eq telnet log", "20 permit ip 10.1.10.0 0.0.0.255 any",
                         "30 deny ip any any log"],
            "SERVERS-OUT": ["10 permit tcp 10.1.0.0 0.0.255.255 host 10.1.20.10 eq 445",
                            "20 deny tcp any host 10.1.20.10 eq 445 log", "30 permit ip any any"],
        },
    },
}

# ==== PAN-OS firewalls (Panorama managed) ===================================================
SERIAL_DC1_A, SERIAL_DC1_B, SERIAL_AWS1 = "013201000101", "013201000102", "007951000123"
FW_AWS_INSTANCE = rid("i", "fw-aws-1")

PANOS: dict[str, dict[str, Any]] = {
    "fw-dc1": {
        "hostname": "fw-dc1", "model": "PA-3420", "version": "11.1.4-h7", "mgmt": "10.255.1.1",
        "serials": [SERIAL_DC1_A, SERIAL_DC1_B], "device_group": "DC",
        "interfaces": [  # name, ip, zone
            ("ethernet1/1", "10.0.0.2/30", "trust"),
            ("ethernet1/3", "10.1.30.1/24", "dmz"),
            ("ethernet1/4", "203.0.113.2/24", "untrust"),
            ("tunnel.1", "169.254.10.2/30", "vpn-aws"),
        ],
        "routes": [
            ("0.0.0.0/0", "203.0.113.1", "ethernet1/4"),
            ("10.1.0.0/16", "10.0.0.1", "ethernet1/1"),
            ("10.50.0.0/16", "10.0.0.1", "ethernet1/1"),
            ("100.64.0.0/16", "10.0.0.1", "ethernet1/1"),
            ("10.20.0.0/16", "169.254.10.1", "tunnel.1"),
            ("10.30.0.0/16", "169.254.10.1", "tunnel.1"),
            ("10.100.0.0/16", "169.254.10.1", "tunnel.1"),
        ],
        # Panorama device group DC, pre-rulebase. Matching uses pre-NAT addresses, post-NAT zones.
        "security": [
            {"name": "allow-corp-to-aws", "from": ["trust"], "to": ["vpn-aws"],
             "source": ["10.1.0.0/16", "10.50.0.0/16", "100.64.0.0/16"], "destination": ["10.20.0.0/16", "10.30.0.0/16"],
             "application": ["any"], "service": ["any"], "action": "allow"},
            # nettrace evaluates a return flow as a NEW session (it does not read session tables), so the lab has
            # explicit rules for the reply direction; a real firewall also lets replies of an allowed session through.
            {"name": "allow-aws-reply-to-corp", "from": ["vpn-aws"], "to": ["trust"],
             "source": ["10.20.0.0/16", "10.30.0.0/16"], "destination": ["10.1.0.0/16", "10.50.0.0/16", "100.64.0.0/16"],
             "application": ["any"], "service": ["any"], "action": "allow"},
            {"name": "allow-web-inbound", "from": ["untrust"], "to": ["dmz"], "source": ["any"],
             "destination": ["203.0.113.10"], "application": ["ssl", "web-browsing"],
             "service": ["application-default"], "action": "allow"},
            {"name": "allow-internet-out", "from": ["trust"], "to": ["untrust"], "source": ["10.1.0.0/16"],
             "destination": ["any"], "application": ["any"], "service": ["tcp/80", "tcp/443"], "action": "allow"},
            {"name": "deny-all-log", "from": ["any"], "to": ["any"], "source": ["any"], "destination": ["any"],
             "application": ["any"], "service": ["any"], "action": "deny"},
        ],
        "nat": [
            {"name": "dnat-www", "from": ["untrust"], "to": ["untrust"], "source": ["any"],
             "destination": ["203.0.113.10"], "service": ["tcp/443", "tcp/80"],
             "dnat": {"address": "10.1.30.10"}},
            {"name": "snat-internet", "from": ["trust"], "to": ["untrust"], "source": ["10.1.0.0/16"],
             "destination": ["any"], "service": ["any"], "snat_interface": "ethernet1/4"},
        ],
    },
    "fw-aws-1": {
        "hostname": "fw-aws-1", "model": "PA-VM", "version": "11.1.4-h7", "mgmt": "10.100.3.10",
        "serials": [SERIAL_AWS1], "device_group": "AWS",
        "interfaces": [
            ("ethernet1/1", "10.100.1.10/24", "from-tgw"),
            ("ethernet1/2", "10.100.2.10/24", "to-tgw"),
        ],
        "routes": [
            ("0.0.0.0/0", "10.100.2.1", "ethernet1/2"),
            ("10.0.0.0/8", "10.100.2.1", "ethernet1/2"),
            ("100.64.0.0/10", "10.100.2.1", "ethernet1/2"),
        ],
        "security": [
            {"name": "deny-onprem-to-db", "from": ["from-tgw"], "to": ["to-tgw"],
             "source": ["10.1.0.0/16", "10.50.0.0/16", "100.64.0.0/16"], "destination": ["10.20.2.0/24"],
             "application": ["any"], "service": ["any"], "action": "deny"},
            {"name": "allow-corp-to-prod-web", "from": ["from-tgw"], "to": ["to-tgw"],
             "source": ["10.0.0.0/8", "100.64.0.0/16"], "destination": ["10.20.1.0/24"],
             "application": ["any"], "service": ["tcp/443", "tcp/80"], "action": "allow"},
            {"name": "allow-prod-reply-to-corp", "from": ["from-tgw"], "to": ["to-tgw"],
             "source": ["10.20.0.0/16"], "destination": ["10.1.0.0/16", "10.50.0.0/16", "100.64.0.0/16"],
             "application": ["any"], "service": ["any"], "action": "allow"},
            {"name": "allow-prod-to-shared-dns", "from": ["from-tgw"], "to": ["to-tgw"],
             "source": ["10.20.0.0/16"], "destination": ["10.30.1.53"], "application": ["dns"],
             "service": ["application-default"], "action": "allow"},
            {"name": "allow-prod-internet", "from": ["from-tgw"], "to": ["to-tgw"], "source": ["10.20.0.0/16"],
             "destination": ["any"], "application": ["any"], "service": ["tcp/443"], "action": "allow"},
            {"name": "deny-all-log", "from": ["any"], "to": ["any"], "source": ["any"], "destination": ["any"],
             "application": ["any"], "service": ["any"], "action": "deny"},
        ],
        "nat": [],
    },
}

PANORAMA = {
    "hostname": "panorama-01", "version": "11.1.4", "host": "panorama.acme.example",
    "device_groups": {"DC": "Global", "AWS": "Global", "Global": None},
    "ha": {SERIAL_DC1_A: ("active", SERIAL_DC1_B), SERIAL_DC1_B: ("passive", SERIAL_DC1_A)},
    "hostnames": {SERIAL_DC1_A: "fw-dc1-a", SERIAL_DC1_B: "fw-dc1-b", SERIAL_AWS1: "fw-aws-1"},
    "mgmt": {SERIAL_DC1_A: "10.255.1.1", SERIAL_DC1_B: "10.255.1.2", SERIAL_AWS1: "10.100.3.10"},
}

# App-ID default ports used for `application-default` in the simulators.
APP_PORTS = {"ssl": [("tcp", 443)], "web-browsing": [("tcp", 80)], "ssh": [("tcp", 22)], "dns": [("udp", 53), ("tcp", 53)],
             "ms-ds-smb": [("tcp", 445)], "postgres": [("tcp", 5432)], "ldap": [("tcp", 389)], "telnet": [("tcp", 23)]}

# ==== Prisma Access (Strata Cloud Manager) ====================================================
SCM = {
    "rules": {
        "Mobile Users": [
            {"name": "block-ssh-from-mobile", "from": ["trust"], "to": ["any"], "source": ["any"], "destination": ["any"],
             "application": ["ssh"], "service": ["application-default"], "action": "deny"},
            {"name": "allow-corp-web", "from": ["trust"], "to": ["trust"], "source": ["MU-pool"],
             "destination": ["corp-nets"], "application": ["any"], "service": ["svc-https"], "action": "allow"},
            {"name": "allow-corp-dns", "from": ["trust"], "to": ["trust"], "source": ["MU-pool"],
             "destination": ["corp-dns"], "application": ["any"], "service": ["svc-dns"], "action": "allow"},
            {"name": "allow-internet", "from": ["trust"], "to": ["untrust"], "source": ["MU-pool"], "destination": ["any"],
             "application": ["any"], "service": ["svc-https"], "action": "allow"},
        ],
        "Remote Networks": [
            {"name": "allow-branch-to-dc", "from": ["trust"], "to": ["trust"], "source": ["branch-nets"],
             "destination": ["corp-nets"], "application": ["any"], "service": ["any"], "action": "allow"},
        ],
    },
    "objects": {
        "addresses": [{"name": "MU-pool", "ip_netmask": "100.64.0.0/16"}, {"name": "corp-10", "ip_netmask": "10.0.0.0/8"},
                      {"name": "branch-12", "ip_netmask": "10.50.12.0/24"}, {"name": "corp-dns", "ip_netmask": "10.30.1.53/32"}],
        "address-groups": [{"name": "corp-nets", "static": ["corp-10"]}, {"name": "branch-nets", "static": ["branch-12"]}],
        "services": [{"name": "svc-https", "protocol": {"tcp": {"port": "443"}}},
                     {"name": "svc-dns", "protocol": {"udp": {"port": "53"}}}],
        "service-groups": [],
        "application-groups": [],
        "application-filters": [],
    },
}

# ==== AWS ================================================================================
TGW = rid("tgw", "tgw")
TGW_RT_SPOKES, TGW_RT_INSPECTION = rid("tgw-rtb", "spokes"), rid("tgw-rtb", "inspection")
ATT_VPN, ATT_INSP = rid("tgw-attach", "vpn-dc1"), rid("tgw-attach", "inspection")
ATT_PROD, ATT_SHARED = rid("tgw-attach", "prod"), rid("tgw-attach", "shared")
VPC_INSP, VPC_PROD, VPC_SHARED = rid("vpc", "inspection"), rid("vpc", "prod"), rid("vpc", "shared")
IGW_INSP = rid("igw", "inspection")
NAT_INSP = rid("nat", "inspection")
ENI = {name: rid("eni", name) for name in ("fw-trust", "fw-untrust", "web01", "db01", "dns01",
                                           "ep-tools", "nlb-tools", "tools01")}

# PrivateLink path (D21): web01 -> interface endpoint in app-prod -> endpoint service owned by shared-services ->
# internal NLB -> target group -> instance tools01.
EP_TOOLS_IP, NLB_TOOLS_IP, TOOLS01_IP = "10.20.3.20", "10.30.2.10", "10.30.3.40"
VPCE_TOOLS = rid("vpce", "tools")
VPCE_SVC_ID = rid("vpce-svc", "tools")
VPCE_SVC_NAME = f"com.amazonaws.vpce.{REGION}.{VPCE_SVC_ID}"
TOOLS01_INSTANCE = rid("i", "tools01")
NLB_NAME = "tools-nlb"
NLB_ID = rid("nlb", NLB_NAME, 17).split("-", 1)[1][:16]  # 16 hex characters, like a real load balancer id
NLB_ARN = f"arn:aws:elasticloadbalancing:{REGION}:{ACCT_SHARED}:loadbalancer/net/{NLB_NAME}/{NLB_ID}"
NLB_LISTENER_ARN = f"arn:aws:elasticloadbalancing:{REGION}:{ACCT_SHARED}:listener/net/{NLB_NAME}/{NLB_ID}/{NLB_ID[::-1]}"
TG_NAME = "tools-tg"
TG_ARN = (f"arn:aws:elasticloadbalancing:{REGION}:{ACCT_SHARED}:targetgroup/{TG_NAME}/"
          f"{rid('tg', TG_NAME, 17).split('-', 1)[1][:16]}")


def _aws_model() -> dict[str, Any]:
    """AWS API-shaped resources. sim_aws answers Describe/Search calls from this."""
    def subnet(name: str, acct: str, vpc: str, cidr: str) -> dict[str, Any]:
        return {"SubnetId": rid("subnet", name), "VpcId": vpc, "CidrBlock": cidr, "AvailabilityZone": AZ,
                "AvailabilityZoneId": AZ_ID, "OwnerId": acct, "Tags": [{"Key": "Name", "Value": name}]}

    s = {n: subnet(n, a, v, c) for n, a, v, c in (
        ("insp-tgw", ACCT_NET, VPC_INSP, "10.100.0.0/28"), ("insp-fw-trust", ACCT_NET, VPC_INSP, "10.100.1.0/24"),
        ("insp-fw-untrust", ACCT_NET, VPC_INSP, "10.100.2.0/24"),
        ("prod-tgw", ACCT_PROD, VPC_PROD, "10.20.0.0/28"), ("prod-app", ACCT_PROD, VPC_PROD, "10.20.1.0/24"),
        ("prod-db", ACCT_PROD, VPC_PROD, "10.20.2.0/24"),
        ("shared-tgw", ACCT_SHARED, VPC_SHARED, "10.30.0.0/28"), ("shared-svc", ACCT_SHARED, VPC_SHARED, "10.30.1.0/24"),
        ("prod-endpoints", ACCT_PROD, VPC_PROD, "10.20.3.0/24"), ("shared-nlb", ACCT_SHARED, VPC_SHARED, "10.30.2.0/24"),
        ("shared-tools", ACCT_SHARED, VPC_SHARED, "10.30.3.0/24"))}

    def local(cidr: str) -> dict[str, Any]:
        return {"DestinationCidrBlock": cidr, "GatewayId": "local", "State": "active"}

    def rtb(name: str, acct: str, vpc: str, subnets: list[str], routes: list[dict[str, Any]], main: bool = False) -> dict[str, Any]:
        assoc = [{"SubnetId": s[x]["SubnetId"], "Main": False} for x in subnets] + ([{"Main": True}] if main else [])
        return {"RouteTableId": rid("rtb", name), "VpcId": vpc, "OwnerId": acct, "Associations": assoc,
                "Routes": [{**r, "State": r.get("State", "active")} for r in routes],
                "Tags": [{"Key": "Name", "Value": name}]}

    route_tables = [
        rtb("insp-tgw-rt", ACCT_NET, VPC_INSP, ["insp-tgw"],
            [local("10.100.0.0/16"), {"DestinationCidrBlock": "0.0.0.0/0", "NetworkInterfaceId": ENI["fw-trust"]}]),
        rtb("insp-fw-rt", ACCT_NET, VPC_INSP, ["insp-fw-trust", "insp-fw-untrust"],
            [local("10.100.0.0/16"), {"DestinationCidrBlock": "10.0.0.0/8", "TransitGatewayId": TGW},
             {"DestinationCidrBlock": "100.64.0.0/10", "TransitGatewayId": TGW},
             {"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": IGW_INSP}], main=True),
        rtb("prod-rt", ACCT_PROD, VPC_PROD, ["prod-app", "prod-db", "prod-tgw", "prod-endpoints"],
            [local("10.20.0.0/16"), {"DestinationCidrBlock": "0.0.0.0/0", "TransitGatewayId": TGW}], main=True),
        rtb("shared-rt", ACCT_SHARED, VPC_SHARED, ["shared-svc", "shared-tgw", "shared-nlb", "shared-tools"],
            [local("10.30.0.0/16"), {"DestinationCidrBlock": "0.0.0.0/0", "TransitGatewayId": TGW}], main=True),
    ]

    def entry(n: int, egress: bool, action: str, cidr: str, proto: str = "-1", ports: tuple[int, int] | None = None) -> dict[str, Any]:
        e = {"RuleNumber": n, "Egress": egress, "RuleAction": action, "CidrBlock": cidr, "Protocol": proto}
        if ports:
            e["PortRange"] = {"From": ports[0], "To": ports[1]}
        return e

    def default_entries() -> list[dict[str, Any]]:
        return [entry(100, False, "allow", "0.0.0.0/0"), entry(32767, False, "deny", "0.0.0.0/0"),
                entry(100, True, "allow", "0.0.0.0/0"), entry(32767, True, "deny", "0.0.0.0/0")]

    def nacl(name: str, acct: str, vpc: str, subnets: list[str], entries: list[dict[str, Any]]) -> dict[str, Any]:
        return {"NetworkAclId": rid("acl", name), "VpcId": vpc, "OwnerId": acct,
                "Associations": [{"SubnetId": s[x]["SubnetId"]} for x in subnets], "Entries": entries,
                "Tags": [{"Key": "Name", "Value": name}]}

    nacls = [
        nacl("insp-default", ACCT_NET, VPC_INSP, ["insp-tgw", "insp-fw-trust", "insp-fw-untrust"], default_entries()),
        # prod-default also has an outbound deny to the branch-12 prefix (preset return-blocked): the request gets in,
        # the reply is dropped. NACLs are stateless, so this is a real block of the return direction.
        nacl("prod-default", ACCT_PROD, VPC_PROD, ["prod-app", "prod-tgw", "prod-endpoints"],
             [entry(90, True, "deny", "10.50.12.0/24"), *default_entries()]),
        nacl("prod-db-nacl", ACCT_PROD, VPC_PROD, ["prod-db"], [
            entry(100, False, "allow", "10.20.1.0/24", "6", (5432, 5432)), entry(32767, False, "deny", "0.0.0.0/0"),
            entry(100, True, "allow", "10.20.1.0/24", "6", (1024, 65535)), entry(32767, True, "deny", "0.0.0.0/0")]),
        nacl("shared-default", ACCT_SHARED, VPC_SHARED, ["shared-svc", "shared-tgw", "shared-nlb", "shared-tools"],
             default_entries()),
    ]

    def perm(proto: str, lo: int | None, hi: int | None, cidrs: list[str] = (), groups: list[str] = ()) -> dict[str, Any]:
        p = {"IpProtocol": proto, "IpRanges": [{"CidrIp": c} for c in cidrs], "Ipv6Ranges": [], "PrefixListIds": [],
             "UserIdGroupPairs": [{"GroupId": g} for g in groups]}
        if lo is not None:
            p.update(FromPort=lo, ToPort=hi)
        return p

    all_out = [perm("-1", None, None, ["0.0.0.0/0"])]
    sg = {n: rid("sg", n) for n in ("fw", "web", "db", "dns", "ep", "nlb", "tools")}
    security_groups = [
        {"GroupId": sg["fw"], "GroupName": "vmseries-data", "VpcId": VPC_INSP, "OwnerId": ACCT_NET,
         "IpPermissions": [perm("-1", None, None, ["0.0.0.0/0"])], "IpPermissionsEgress": all_out},
        {"GroupId": sg["web"], "GroupName": "web-tier", "VpcId": VPC_PROD, "OwnerId": ACCT_PROD,
         "IpPermissions": [perm("tcp", 443, 443, ["10.0.0.0/8"]), perm("tcp", 80, 80, ["10.0.0.0/8"])],
         "IpPermissionsEgress": all_out},
        {"GroupId": sg["db"], "GroupName": "db-tier", "VpcId": VPC_PROD, "OwnerId": ACCT_PROD,
         "IpPermissions": [perm("tcp", 5432, 5432, groups=[sg["web"]])], "IpPermissionsEgress": all_out},
        {"GroupId": sg["dns"], "GroupName": "dns-resolvers", "VpcId": VPC_SHARED, "OwnerId": ACCT_SHARED,
         "IpPermissions": [perm("udp", 53, 53, ["10.0.0.0/8"]), perm("tcp", 53, 53, ["10.0.0.0/8"])],
         "IpPermissionsEgress": all_out},
        # PrivateLink: the endpoint takes 443 and 8080 from its own VPC; the NLB (inbound rules on PrivateLink traffic
        # switched off) is only open to its own VPC by rule; the tools server trusts the NLB's security group.
        {"GroupId": sg["ep"], "GroupName": "tools-endpoint", "VpcId": VPC_PROD, "OwnerId": ACCT_PROD,
         "IpPermissions": [perm("tcp", 443, 443, ["10.20.0.0/16"]), perm("tcp", 8080, 8080, ["10.20.0.0/16"])],
         "IpPermissionsEgress": all_out},
        {"GroupId": sg["nlb"], "GroupName": "tools-nlb", "VpcId": VPC_SHARED, "OwnerId": ACCT_SHARED,
         "IpPermissions": [perm("tcp", 443, 443, ["10.30.0.0/16"])], "IpPermissionsEgress": all_out},
        {"GroupId": sg["tools"], "GroupName": "tools-server", "VpcId": VPC_SHARED, "OwnerId": ACCT_SHARED,
         "IpPermissions": [perm("tcp", 8443, 8443, groups=[sg["nlb"]])], "IpPermissionsEgress": all_out},
    ]

    def eni(name: str, acct: str, sub: str, ip: str, group: str, *, instance: str | None = None, index: int = 0,
            sdc: bool = True, desc: str = "", itype: str = "interface") -> dict[str, Any]:
        e = {"NetworkInterfaceId": ENI[name], "SubnetId": s[sub]["SubnetId"], "VpcId": s[sub]["VpcId"], "OwnerId": acct,
             "AvailabilityZone": AZ, "PrivateIpAddress": ip, "PrivateIpAddresses": [{"PrivateIpAddress": ip, "Primary": True}],
             "Groups": [{"GroupId": sg[group]}], "SourceDestCheck": sdc, "InterfaceType": itype,
             "Description": desc, "Status": "in-use"}
        if itype in ("vpc_endpoint", "network_load_balancer"):
            e["RequesterManaged"] = True  # AWS creates and owns these in the customer's subnet
        if instance:
            e["Attachment"] = {"InstanceId": instance, "DeviceIndex": index, "Status": "attached"}
        return e

    enis = [
        eni("fw-trust", ACCT_NET, "insp-fw-trust", "10.100.1.10", "fw", instance=FW_AWS_INSTANCE, index=1, sdc=False,
            desc="fw-aws-1 ethernet1/1"),
        eni("fw-untrust", ACCT_NET, "insp-fw-untrust", "10.100.2.10", "fw", instance=FW_AWS_INSTANCE, index=2, sdc=False,
            desc="fw-aws-1 ethernet1/2"),
        eni("web01", ACCT_PROD, "prod-app", "10.20.1.50", "web", instance=rid("i", "web01"), desc="web01"),
        eni("db01", ACCT_PROD, "prod-db", "10.20.2.10", "db", desc="RDSNetworkInterface (orders-db)"),
        eni("dns01", ACCT_SHARED, "shared-svc", "10.30.1.53", "dns", instance=rid("i", "dns01"), desc="dns01"),
        eni("ep-tools", ACCT_PROD, "prod-endpoints", EP_TOOLS_IP, "ep", itype="vpc_endpoint",
            desc=f"VPC Endpoint Interface {VPCE_TOOLS}"),
        eni("nlb-tools", ACCT_SHARED, "shared-nlb", NLB_TOOLS_IP, "nlb", itype="network_load_balancer",
            desc=f"ELB net/{NLB_NAME}/{NLB_ID}"),
        eni("tools01", ACCT_SHARED, "shared-tools", TOOLS01_IP, "tools", instance=TOOLS01_INSTANCE, desc="tools01"),
    ]

    dns_base = f"{VPCE_SVC_ID}.vpce-svc.{REGION}.vpce.amazonaws.com"
    endpoint_services = [{  # DescribeVpcEndpointServices: what a consumer sees (Owner is the provider's account)
        "ServiceName": VPCE_SVC_NAME, "ServiceId": VPCE_SVC_ID, "ServiceType": [{"ServiceType": "Interface"}],
        "AvailabilityZones": [AZ], "Owner": ACCT_SHARED, "BaseEndpointDnsNames": [dns_base],
        "VpcEndpointPolicySupported": False, "AcceptanceRequired": False, "ManagesVpcEndpoints": False,
        "Tags": [{"Key": "Name", "Value": "tools"}]}]
    vpc_endpoints = [{
        "VpcEndpointId": VPCE_TOOLS, "VpcEndpointType": "Interface", "VpcId": VPC_PROD, "ServiceName": VPCE_SVC_NAME,
        "State": "available", "SubnetIds": [s["prod-endpoints"]["SubnetId"]],
        "Groups": [{"GroupId": sg["ep"], "GroupName": "tools-endpoint"}],
        "PrivateDnsEnabled": False, "RequesterManaged": False, "NetworkInterfaceIds": [ENI["ep-tools"]],
        "OwnerId": ACCT_PROD, "RouteTableIds": [], "DnsEntries": [], "Tags": [{"Key": "Name", "Value": "tools"}]}]
    service_configs = {ACCT_SHARED: [{  # DescribeVpcEndpointServiceConfigurations: the provider's own view
        "ServiceType": [{"ServiceType": "Interface"}], "ServiceId": VPCE_SVC_ID, "ServiceName": VPCE_SVC_NAME,
        "ServiceState": "Available", "AvailabilityZones": [AZ], "AcceptanceRequired": False,
        "ManagesVpcEndpoints": False, "NetworkLoadBalancerArns": [NLB_ARN], "BaseEndpointDnsNames": [dns_base]}]}

    def attrs(**kv: str) -> list[dict[str, str]]:  # "a__b" -> key "a.b"
        return [{"Key": k.replace("__", "."), "Value": v} for k, v in kv.items()]

    elb = {ACCT_SHARED: {
        "load_balancers": [{
            "LoadBalancerArn": NLB_ARN, "DNSName": f"{NLB_NAME}-{NLB_ID}.elb.{REGION}.amazonaws.com",
            "LoadBalancerName": NLB_NAME, "Scheme": "internal", "VpcId": VPC_SHARED, "State": {"Code": "active"},
            "Type": "network",
            "AvailabilityZones": [{"ZoneName": AZ, "SubnetId": s["shared-nlb"]["SubnetId"],
                                   "LoadBalancerAddresses": []}],
            "SecurityGroups": [sg["nlb"]], "IpAddressType": "ipv4",
            "EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic": "off"}],
        "listeners": [{
            "ListenerArn": NLB_LISTENER_ARN, "LoadBalancerArn": NLB_ARN, "Port": 443, "Protocol": "TCP",
            "DefaultActions": [{"Type": "forward", "TargetGroupArn": TG_ARN, "Order": 1,
                                "ForwardConfig": {"TargetGroups": [{"TargetGroupArn": TG_ARN, "Weight": 1}],
                                                  "TargetGroupStickinessConfig": {"Enabled": False}}}]}],
        "target_groups": [{
            "TargetGroupArn": TG_ARN, "TargetGroupName": TG_NAME, "Protocol": "TCP", "Port": 8443, "VpcId": VPC_SHARED,
            "HealthCheckProtocol": "TCP", "HealthCheckPort": "traffic-port", "HealthCheckEnabled": True,
            "HealthyThresholdCount": 3, "UnhealthyThresholdCount": 3, "HealthCheckIntervalSeconds": 30,
            "LoadBalancerArns": [NLB_ARN], "TargetType": "instance", "IpAddressType": "ipv4"}],
        "target_health": {TG_ARN: [{
            "Target": {"Id": TOOLS01_INSTANCE, "Port": 8443}, "HealthCheckPort": "8443",
            "TargetHealth": {"State": "healthy"}}]},
        "tg_attributes": {TG_ARN: attrs(**{"preserve_client_ip__enabled": "true", "proxy_protocol_v2__enabled": "false",
                                           "load_balancing__cross_zone__enabled": "use_load_balancer_configuration",
                                           "deregistration_delay__timeout_seconds": "300"})},
        "lb_attributes": {NLB_ARN: attrs(**{"load_balancing__cross_zone__enabled": "false",
                                            "deletion_protection__enabled": "false"})},
    }}

    def att(att_id: str, rtype: str, res: str, owner: str, rtb: str) -> dict[str, Any]:
        return {"TransitGatewayAttachmentId": att_id, "TransitGatewayId": TGW, "TransitGatewayOwnerId": ACCT_NET,
                "ResourceOwnerId": owner, "ResourceType": rtype, "ResourceId": res, "State": "available",
                "Association": {"TransitGatewayRouteTableId": rtb, "State": "associated"}}

    tgw_attachments = [
        att(ATT_VPN, "vpn", rid("vpn", "dc1"), ACCT_NET, TGW_RT_SPOKES),
        att(ATT_INSP, "vpc", VPC_INSP, ACCT_NET, TGW_RT_INSPECTION),
        att(ATT_PROD, "vpc", VPC_PROD, ACCT_PROD, TGW_RT_SPOKES),
        att(ATT_SHARED, "vpc", VPC_SHARED, ACCT_SHARED, TGW_RT_SPOKES),
    ]

    def vpc_att(att_id: str, vpc: str, owner: str, sub: str, appliance: bool = False) -> dict[str, Any]:
        return {"TransitGatewayAttachmentId": att_id, "TransitGatewayId": TGW, "VpcId": vpc, "VpcOwnerId": owner,
                "State": "available", "SubnetIds": [s[sub]["SubnetId"]],
                "Options": {"ApplianceModeSupport": "enable" if appliance else "disable"}}

    vpc_attachments = [
        vpc_att(ATT_INSP, VPC_INSP, ACCT_NET, "insp-tgw", appliance=True),
        vpc_att(ATT_PROD, VPC_PROD, ACCT_PROD, "prod-tgw"),
        vpc_att(ATT_SHARED, VPC_SHARED, ACCT_SHARED, "shared-tgw"),
    ]

    def tgw_route(cidr: str, att_id: str, rtype: str, res: str, kind: str = "propagated") -> dict[str, Any]:
        return {"DestinationCidrBlock": cidr, "Type": kind, "State": "active",
                "TransitGatewayAttachments": [{"TransitGatewayAttachmentId": att_id, "ResourceType": rtype, "ResourceId": res}]}

    tgw_routes = {
        # 10.1.20.0/24 (DC servers) has a static route straight to the VPN: replies from a spoke to it skip the
        # inspection VPC (preset return-asymmetric). Requests from the DC still enter through inspection (0.0.0.0/0).
        TGW_RT_SPOKES: [tgw_route("0.0.0.0/0", ATT_INSP, "vpc", VPC_INSP, "static"),
                        tgw_route("10.1.20.0/24", ATT_VPN, "vpn", rid("vpn", "dc1"), "static")],
        TGW_RT_INSPECTION: [
            tgw_route("10.20.0.0/16", ATT_PROD, "vpc", VPC_PROD), tgw_route("10.30.0.0/16", ATT_SHARED, "vpc", VPC_SHARED),
            tgw_route("10.1.0.0/16", ATT_VPN, "vpn", rid("vpn", "dc1")), tgw_route("10.50.0.0/16", ATT_VPN, "vpn", rid("vpn", "dc1")),
            tgw_route("100.64.0.0/16", ATT_VPN, "vpn", rid("vpn", "dc1"))],
    }
    vpcs = [{"VpcId": VPC_INSP, "CidrBlock": "10.100.0.0/16", "OwnerId": ACCT_NET, "State": "available"},
            {"VpcId": VPC_PROD, "CidrBlock": "10.20.0.0/16", "OwnerId": ACCT_PROD, "State": "available"},
            {"VpcId": VPC_SHARED, "CidrBlock": "10.30.0.0/16", "OwnerId": ACCT_SHARED, "State": "available"}]
    def instance(name: str, iid: str, acct: str, state: str = "running") -> dict[str, Any]:
        """DescribeInstances shape, as far as the web map reads it (Name tag and state)."""
        return {"OwnerId": acct, "Instances": [{"InstanceId": iid, "InstanceType": "t3.small", "State": {"Name": state},
                                                "Tags": [{"Key": "Name", "Value": name}]}]}

    instances = [instance("fw-aws-1", FW_AWS_INSTANCE, ACCT_NET), instance("web01", rid("i", "web01"), ACCT_PROD),
                 instance("dns01", rid("i", "dns01"), ACCT_SHARED), instance("tools01", TOOLS01_INSTANCE, ACCT_SHARED)]
    # One NAT gateway in the inspection VPC's untrust subnet (nothing in the demo routes through it; the web map shows it).
    nat_gateways = [{"NatGatewayId": NAT_INSP, "VpcId": VPC_INSP, "SubnetId": s["insp-fw-untrust"]["SubnetId"],
                     "State": "available", "ConnectivityType": "public", "OwnerId": ACCT_NET,
                     "NatGatewayAddresses": [{"PrivateIp": "10.100.2.200", "PublicIp": "203.0.113.50",
                                              "NetworkInterfaceId": rid("eni", "nat-insp")}],
                     "Tags": [{"Key": "Name", "Value": "insp-nat"}]}]
    return {
        "instances": instances, "nat_gateways": nat_gateways,
        "vpcs": vpcs, "subnets": list(s.values()), "route_tables": route_tables, "nacls": nacls,
        "security_groups": security_groups, "enis": enis,
        "tgws": [{"TransitGatewayId": TGW, "OwnerId": ACCT_NET, "State": "available"}],
        "tgw_attachments": tgw_attachments, "vpc_attachments": vpc_attachments, "tgw_routes": tgw_routes,
        "vpc_endpoints": vpc_endpoints, "endpoint_services": endpoint_services, "service_configs": service_configs,
        "elb": elb,
    }


AWS = _aws_model()

# ==== demo inventory =====================================================================
INVENTORY = f"""
# Acme Corp demo lab (simulated). Generated by nettrace.demo.lab.
panorama:
  host: {PANORAMA['host']}
  api_key_env: NETTRACE_PANORAMA_API_KEY
devices:
  - name: core-rtr1
    platform: cisco_iosxe
    host: 10.255.0.1
    site: DC1
  - name: fw-dc1                # listed by the HA *passive* serial; nettrace follows HA to the active member
    platform: panos
    serial: "{SERIAL_DC1_B}"
    site: DC1
  - name: fw-aws-1
    platform: panos
    serial: "{SERIAL_AWS1}"
    aws:
      account: network
      region: {REGION}
      instance_id: {FW_AWS_INSTANCE}
networks:
  - {{prefix: 10.1.10.0/24, gateway: core-rtr1}}
  - {{prefix: 10.1.20.0/24, gateway: core-rtr1}}
  - {{prefix: 10.1.30.0/24, gateway: fw-dc1}}
  - {{prefix: 10.1.40.0/24, gateway: core-rtr1}}
aws:
  regions: [{REGION}]
  accounts:
    - {{name: network, account_id: "{ACCT_NET}"}}
    - {{name: app-prod, account_id: "{ACCT_PROD}"}}
    - {{name: shared-services, account_id: "{ACCT_SHARED}"}}
prisma_access:
  mobile_users: {{folder: Mobile Users, ip_pools: [100.64.0.0/16]}}
  remote_networks:
    folder: Remote Networks
    networks: [{{name: branch-12, prefixes: [10.50.12.0/24]}}]
  service_connections: [{{name: SC-US-East, routes: [10.0.0.0/8]}}]
links:
  - name: dc1-aws-vpn
    a: {{device: fw-dc1, interface: tunnel.1}}
    b: {{aws: {{tgw_attachment: {ATT_VPN}, account: network, region: {REGION}}}}}
  - name: dc1-prisma-sc
    a: {{device: core-rtr1, interface: Tunnel200}}
    b: {{prisma_access: {{service_connection: SC-US-East}}}}
  - name: dc1-internet
    a: {{device: fw-dc1, interface: ethernet1/4}}
    b: {{external: "Internet (ISP-A)"}}
"""

# ==== preset scenarios ======================================================================
PRESETS: list[dict[str, Any]] = [
    {"id": "dc-to-prod-web", "title": "DC user → prod web (HTTPS)", "expect": "REACHABLE",
     "story": "Full hybrid path: IOS-XE ACL, DC firewall via Panorama (HA follow), IPsec to TGW, "
              "inspection VPC VM-Series, TGW back to the app-prod account, SG.",
     "flow": {"src": "10.1.10.25", "dst": "10.20.1.50", "port": 443, "protocol": "tcp"}},
    {"id": "dc-to-prod-db", "title": "DC user → prod database", "expect": "BLOCKED",
     "story": "The AWS inspection firewall denies on-prem access to the DB subnet.",
     "flow": {"src": "10.1.10.25", "dst": "10.20.2.10", "port": 5432, "protocol": "tcp"}},
    {"id": "mobile-to-prod-web", "title": "Remote worker → prod web", "expect": "BLOCKED",
     "story": "Prisma Access and both firewalls allow it, but the web SG only allows 10.0.0.0/8 and "
              "misses the mobile-user pool 100.64.0.0/16.",
     "flow": {"src": "100.64.3.7", "dst": "10.20.1.50", "port": 443, "protocol": "tcp", "application": "ssl",
              "user": "alice"}},
    {"id": "mobile-ssh", "title": "Remote worker SSH → file server", "expect": "BLOCKED",
     "story": "Blocked at the first hop by a Prisma Access App-ID rule.",
     "flow": {"src": "100.64.3.7", "dst": "10.1.20.10", "port": 22, "protocol": "tcp", "application": "ssh"}},
    {"id": "branch-smb", "title": "Branch → file server (SMB)", "expect": "BLOCKED",
     "story": "Prisma remote network → service connection → core-rtr1, where the outbound ACL on the server "
              "VLAN only allows SMB from DC subnets.",
     "flow": {"src": "10.50.12.40", "dst": "10.1.20.10", "port": 445, "protocol": "tcp"}},
    {"id": "branch-https", "title": "Branch → intranet (HTTPS)", "expect": "REACHABLE",
     "story": "Same path as the SMB case; HTTPS is permitted.",
     "flow": {"src": "10.50.12.40", "dst": "10.1.20.10", "port": 443, "protocol": "tcp"}},
    {"id": "internet-to-www", "title": "Internet → public website", "expect": "REACHABLE",
     "story": "Destination NAT on fw-dc1: 203.0.113.10 → www01 10.1.30.10 in the DMZ (rule from a "
              "Panorama device group).",
     "flow": {"src": "198.51.100.77", "dst": "203.0.113.10", "port": 443, "protocol": "tcp", "application": "ssl",
              "start_at": "fw-dc1"}},
    {"id": "prod-to-dns", "title": "Prod app → shared DNS", "expect": "REACHABLE",
     "story": "Spoke-to-spoke across accounts, forced through the inspection VPC by TGW route tables.",
     "flow": {"src": "10.20.1.50", "dst": "10.30.1.53", "port": 53, "protocol": "udp"}},
    {"id": "prod-to-internet", "title": "Prod app → Internet", "expect": "EXITED",
     "story": "Centralised egress: spoke → TGW → VM-Series → IGW.",
     "flow": {"src": "10.20.1.50", "dst": "52.94.236.248", "port": 443, "protocol": "tcp"}},
    {"id": "dc-to-internet", "title": "DC user → Internet", "expect": "EXITED",
     "story": "Source NAT to the fw-dc1 untrust interface, out the ISP link.",
     "flow": {"src": "10.1.10.25", "dst": "8.8.8.8", "port": 443, "protocol": "tcp"}},
    {"id": "dc-telnet", "title": "DC user telnet → server", "expect": "BLOCKED",
     "story": "Denied by the inbound ACL on the users VLAN of core-rtr1.",
     "flow": {"src": "10.1.10.25", "dst": "10.1.20.10", "port": 23, "protocol": "tcp"}},
    {"id": "guest-nat", "title": "Guest Wi-Fi → Internet (NAT on the router)", "expect": "INCOMPLETE",
     "story": "core-rtr1 has `ip nat inside` on the guest VLAN. nettrace does not evaluate NAT, so the router hop "
              "is UNKNOWN (the real addresses may differ) and the otherwise clean path ends INCOMPLETE.",
     "flow": {"src": "10.1.40.25", "dst": "8.8.8.8", "port": 443, "protocol": "tcp"}},
    {"id": "ipv6-not-evaluated", "title": "IPv6 flow through core-rtr1", "expect": "INCOMPLETE",
     "story": "nettrace evaluates IPv4 only. An IPv6 flow gets an UNKNOWN hop (\"IPv6 is not evaluated\"); "
              "no IPv4 logic runs on it.",
     "flow": {"src": "2001:db8:10::25", "dst": "2001:db8:20::10", "port": 443, "protocol": "tcp",
              "start_at": "core-rtr1"}},
    {"id": "return-symmetric", "title": "DC user → prod web, with return path", "expect": "REACHABLE",
     "story": "Same path as the first scenario, plus the reverse trace (prod web back to the DC user). Both "
              "directions cross core-rtr1, fw-dc1 and fw-aws-1 on the same interfaces: SYMMETRIC.",
     "flow": {"src": "10.1.10.25", "dst": "10.20.1.50", "port": 443, "protocol": "tcp", "return": True}},
    {"id": "return-asymmetric", "title": "DC server → prod web, asymmetric return", "expect": "REACHABLE",
     "story": "The request goes through the inspection VPC (fw-aws-1), but a static TGW route sends the reply "
              "from the spoke straight to the VPN: fw-aws-1 only ever sees one direction. ASYMMETRIC, exit 0 "
              "with a warning.",
     "flow": {"src": "10.1.20.10", "dst": "10.20.1.50", "port": 443, "protocol": "tcp", "return": True}},
    {"id": "return-blocked", "title": "Branch → prod web, reply blocked", "expect": "REACHABLE",
     "story": "The request is allowed end to end, but the stateless NACL on the prod-app subnet denies outbound "
              "traffic to the branch prefix, so the reply never leaves. Forward REACHABLE, return BLOCKED: exit 3.",
     "flow": {"src": "10.50.12.40", "dst": "10.20.1.50", "port": 443, "protocol": "tcp", "return": True}},
    {"id": "prod-to-tools-privatelink", "title": "Prod app → tools server over PrivateLink", "expect": "REACHABLE",
     "story": "web01 connects to its interface endpoint in app-prod. The endpoint service belongs to shared-services: "
              "internal NLB, TCP 443 listener, target group on port 8443, instance tools01. The server sees the NLB "
              "node as the source (PrivateLink never preserves the client address) and port 8443.",
     "flow": {"src": "10.20.1.50", "dst": EP_TOOLS_IP, "port": 443, "protocol": "tcp"}},
    {"id": "prod-to-tools-no-listener", "title": "Prod app → tools endpoint on a port the NLB does not serve",
     "expect": "BLOCKED",
     "story": "The endpoint's security group allows 8080, but the NLB behind the endpoint service only listens on TCP "
              "443: no listener, the connection is refused at the NLB.",
     "flow": {"src": "10.20.1.50", "dst": EP_TOOLS_IP, "port": 8080, "protocol": "tcp"}},
    {"id": "web-to-db", "title": "Prod web → database", "expect": "REACHABLE",
     "story": "Inside one VPC: NACL on the DB subnet and an SG that references the web-tier SG.",
     "flow": {"src": "10.20.1.50", "dst": "10.20.2.10", "port": 5432, "protocol": "tcp"}},
]

# ==== topology (positions are hand-placed, like a saved CML / Packet Tracer lab) ====================
TOPOLOGY: dict[str, Any] = {
    "title": "Acme Corp hybrid network (demo lab)",
    "size": [1720, 1010],
    "groups": [
        {"id": "g-prisma", "label": "Prisma Access", "kind": "prisma", "x": 30, "y": 30, "w": 470, "h": 330},
        {"id": "g-dc1", "label": "DC1 · Ashburn", "kind": "site", "x": 30, "y": 400, "w": 760, "h": 580},
        {"id": "g-aws", "label": f"AWS · {REGION}", "kind": "aws", "x": 830, "y": 30, "w": 860, "h": 950},
        {"id": "g-net", "label": f"network ({ACCT_NET})", "kind": "account", "parent": "g-aws",
         "x": 850, "y": 70, "w": 390, "h": 890},
        {"id": "g-insp", "label": "VPC inspection 10.100.0.0/16", "kind": "vpc", "parent": "g-net",
         "x": 870, "y": 110, "w": 350, "h": 380},
        {"id": "g-prod", "label": f"app-prod ({ACCT_PROD})", "kind": "account", "parent": "g-aws",
         "x": 1260, "y": 70, "w": 410, "h": 440},
        {"id": "g-prodvpc", "label": "VPC prod 10.20.0.0/16", "kind": "vpc", "parent": "g-prod",
         "x": 1280, "y": 110, "w": 370, "h": 380},
        {"id": "g-shared", "label": f"shared-services ({ACCT_SHARED})", "kind": "account", "parent": "g-aws",
         "x": 1260, "y": 540, "w": 410, "h": 420},
        {"id": "g-sharedvpc", "label": "VPC shared 10.30.0.0/16", "kind": "vpc", "parent": "g-shared",
         "x": 1280, "y": 580, "w": 370, "h": 360},
    ],
    "nodes": [
        {"id": "mobile-users", "label": "Mobile users", "sub": "GlobalProtect · 100.64.0.0/16", "kind": "users",
         "x": 120, "y": 130, "group": "g-prisma", "cidrs": ["100.64.0.0/16"]},
        {"id": "branch-12", "label": "branch-12", "sub": "remote network · 10.50.12.0/24", "kind": "lan",
         "x": 120, "y": 275, "group": "g-prisma", "cidrs": ["10.50.12.0/24"]},
        {"id": "prisma-access", "label": "Prisma Access", "sub": "SASE · Mobile Users / RN", "kind": "prisma",
         "x": 370, "y": 200, "group": "g-prisma", "devices": ["prisma-access"]},
        {"id": "internet", "label": "Internet", "sub": "ISP-A / public", "kind": "external", "x": 650, "y": 170,
         "cidrs": ["0.0.0.0/0"]},
        {"id": "users-lan", "label": "Users VLAN 10", "sub": "10.1.10.0/24", "kind": "lan", "x": 130, "y": 520,
         "group": "g-dc1", "cidrs": ["10.1.10.0/24"]},
        {"id": "guest-lan", "label": "Guest VLAN 40", "sub": "10.1.40.0/24 · NAT inside", "kind": "lan", "x": 130,
         "y": 620, "group": "g-dc1", "cidrs": ["10.1.40.0/24"]},
        {"id": "servers-lan", "label": "Servers VLAN 20", "sub": "10.1.20.0/24", "kind": "lan", "x": 130, "y": 720,
         "group": "g-dc1", "cidrs": ["10.1.20.0/24"]},
        {"id": "fs01", "label": "fs01", "sub": "file / intranet · 10.1.20.10", "kind": "host", "x": 130, "y": 880,
         "group": "g-dc1", "cidrs": ["10.1.20.10/32"]},
        {"id": "core-rtr1", "label": "core-rtr1", "sub": "C8300 · IOS-XE 17.12", "kind": "router", "x": 370, "y": 620,
         "group": "g-dc1", "devices": ["core-rtr1"]},
        {"id": "fw-dc1", "label": "fw-dc1", "sub": "PA-3420 HA · Panorama", "kind": "firewall", "x": 620, "y": 620,
         "group": "g-dc1", "devices": ["fw-dc1"]},
        {"id": "dmz-lan", "label": "DMZ", "sub": "10.1.30.0/24", "kind": "lan", "x": 620, "y": 800, "group": "g-dc1",
         "cidrs": ["10.1.30.0/24"]},
        {"id": "www01", "label": "www01", "sub": "10.1.30.10 (NAT 203.0.113.10)", "kind": "host", "x": 620, "y": 920,
         "group": "g-dc1", "cidrs": ["10.1.30.10/32", "203.0.113.10/32"]},
        {"id": "tgw", "label": "Transit Gateway", "sub": TGW, "kind": "tgw", "x": 1045, "y": 640, "group": "g-net",
         "ids": [TGW, TGW_RT_SPOKES, TGW_RT_INSPECTION, ATT_VPN, ATT_INSP, ATT_PROD, ATT_SHARED]},
        {"id": "insp-rtr", "label": "inspection VPC router", "sub": "route tables · NACLs", "kind": "vpc-router",
         "x": 960, "y": 400, "group": "g-insp", "vpcs": [VPC_INSP]},
        {"id": "fw-aws-1", "label": "fw-aws-1", "sub": "VM-Series · Panorama", "kind": "firewall", "x": 1130, "y": 400,
         "group": "g-insp", "devices": ["fw-aws-1"], "ids": [ENI["fw-trust"], ENI["fw-untrust"]]},
        {"id": "igw", "label": "IGW", "sub": IGW_INSP, "kind": "igw", "x": 1045, "y": 200, "group": "g-insp",
         "ids": [IGW_INSP]},
        {"id": "prod-rtr", "label": "prod VPC router", "sub": "prod-rt · NACLs", "kind": "vpc-router", "x": 1360,
         "y": 300, "group": "g-prodvpc", "vpcs": [VPC_PROD]},
        {"id": "web01", "label": "web01", "sub": "10.20.1.50 · web-tier SG", "kind": "host", "x": 1560, "y": 200,
         "group": "g-prodvpc", "cidrs": ["10.20.1.50/32"], "ids": [ENI["web01"]]},
        {"id": "db01", "label": "orders-db", "sub": "10.20.2.10 · RDS", "kind": "host", "x": 1560, "y": 400,
         "group": "g-prodvpc", "cidrs": ["10.20.2.10/32"], "ids": [ENI["db01"]]},
        {"id": "shared-rtr", "label": "shared VPC router", "sub": "shared-rt · NACLs", "kind": "vpc-router", "x": 1360,
         "y": 760, "group": "g-sharedvpc", "vpcs": [VPC_SHARED]},
        {"id": "dns01", "label": "dns01", "sub": "10.30.1.53 · resolver", "kind": "host", "x": 1560, "y": 760,
         "group": "g-sharedvpc", "cidrs": ["10.30.1.53/32"], "ids": [ENI["dns01"]]},
    ],
    "links": [
        {"a": "mobile-users", "b": "prisma-access", "label": "GlobalProtect", "kind": "tunnel"},
        {"a": "branch-12", "b": "prisma-access", "label": "IPsec RN", "kind": "tunnel"},
        {"a": "prisma-access", "b": "core-rtr1", "label": "SC-US-East", "b_if": "Tu200", "kind": "tunnel"},
        {"a": "users-lan", "b": "core-rtr1", "b_if": "Gi2"},
        {"a": "servers-lan", "b": "core-rtr1", "b_if": "Gi3"},
        {"a": "guest-lan", "b": "core-rtr1", "b_if": "Gi4"},
        {"a": "fs01", "b": "servers-lan"},
        {"a": "core-rtr1", "b": "fw-dc1", "a_if": "Gi1", "b_if": "e1/1"},
        {"a": "fw-dc1", "b": "dmz-lan", "a_if": "e1/3"},
        {"a": "www01", "b": "dmz-lan"},
        {"a": "fw-dc1", "b": "internet", "a_if": "e1/4"},
        {"a": "fw-dc1", "b": "tgw", "a_if": "tunnel.1", "label": "IPsec VPN", "kind": "tunnel"},
        {"a": "tgw", "b": "insp-rtr", "label": "attach", "kind": "attachment"},
        {"a": "insp-rtr", "b": "fw-aws-1", "b_if": "e1/1 · e1/2"},
        {"a": "insp-rtr", "b": "igw"},
        {"a": "igw", "b": "internet"},
        {"a": "tgw", "b": "prod-rtr", "label": "attach", "kind": "attachment"},
        {"a": "prod-rtr", "b": "web01"},
        {"a": "prod-rtr", "b": "db01"},
        {"a": "tgw", "b": "shared-rtr", "label": "attach", "kind": "attachment"},
        {"a": "shared-rtr", "b": "dns01"},
    ],
}


# ==== install ======================================================================================
_installed: dict[str, Any] = {}


def install() -> Any:
    """Plug the simulators in and return the demo Inventory. Idempotent."""
    if "inventory" in _installed:
        return _installed["inventory"]
    from nettrace import audit
    from nettrace.demo import sim_aws, sim_cisco, sim_panos, sim_scm
    from nettrace.drivers.aws import AwsEnv
    from nettrace.drivers.cisco_iosxe import CiscoClient
    from nettrace.drivers.panos import XmlApi
    from nettrace.drivers.prisma import ScmClient
    from nettrace.inventory import load_inventory

    # Credentials the drivers ask for. Process-local placeholders; the simulators ignore them.
    for var in ("NETTRACE_CISCO_USERNAME", "NETTRACE_CISCO_PASSWORD", "NETTRACE_PANORAMA_API_KEY",
                "NETTRACE_PANOS_API_KEY", "NETTRACE_SCM_CLIENT_ID", "NETTRACE_SCM_CLIENT_SECRET",
                "NETTRACE_SCM_TSG_ID"):
        os.environ.setdefault(var, "demo")
    tmp = tempfile.mkdtemp(prefix="nettrace-demo-")
    os.environ["NETTRACE_CACHE_DIR"] = tmp  # keep the demo's discovery cache away from the real one

    audit.mark_demo()
    CiscoClient.connection_override = sim_cisco.connect
    XmlApi.session_override = sim_panos.session
    ScmClient.transport_override = sim_scm.get
    AwsEnv.backend_override = sim_aws.backend

    path = os.path.join(tmp, "demo-inventory.yaml")
    with open(path, "w") as fh:
        fh.write(INVENTORY)
    inv = load_inventory(path)
    inv.discovered = discovered_addresses()
    _installed["inventory"] = inv
    return inv


def discovered_addresses() -> dict[str, dict[str, str]]:
    """What `nettrace inventory discover` would learn from the lab's devices."""
    out: dict[str, dict[str, str]] = {}
    for name, dev in CISCO.items():
        for intf in dev["interfaces"]:
            out[intf["ip"].split("/")[0]] = {"device": name, "interface": intf["name"]}
    for name, dev in PANOS.items():
        for ifname, ip, _zone in dev["interfaces"]:
            out[ip.split("/")[0]] = {"device": name, "interface": ifname}
    return out
