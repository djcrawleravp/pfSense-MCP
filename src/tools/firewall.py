"""Firewall tools for pfSense MCP server."""

from datetime import datetime, timezone
from typing import Dict, List, Optional, Union

from ..guardrails import guarded, rate_limited
from ..helpers import (
    MAX_BULK_IPS,
    create_default_sort,
    create_interface_filter,
    create_pagination,
    create_port_filter,
    safe_data_dict,
    sanitize_description,
    validate_ip_address,
    validate_port_value,
)
from ..models import ControlParameters, QueryFilter
from ..server import get_api_client, logger, mcp
from mcp.types import ToolAnnotations


_RULE_TYPES = {"pass", "block", "reject"}
_IP_PROTOCOLS = {"inet", "inet6", "inet46"}
_PROTOCOLS = {
    "tcp", "udp", "tcp/udp", "icmp", "esp", "ah", "gre", "ipv6",
    "igmp", "pim", "ospf", "carp", "pfsync", "any",
}
_STATE_TYPES = {"keep state", "sloppy state", "synproxy state", "none"}
_FLOATING_DIRECTIONS = {"any", "in", "out"}


def _normalize_interfaces(interface: Union[str, List[str]]) -> List[str]:
    """Return a non-empty firewall interface list for the REST API."""
    interfaces = [interface] if isinstance(interface, str) else interface
    if not interfaces or not all(isinstance(value, str) and value for value in interfaces):
        raise ValueError("interface must contain one or more non-empty interface names")
    return interfaces


def _validate_rule_options(
    rule_type: Optional[str] = None,
    ip_protocol: Optional[str] = None,
    protocol: Optional[str] = None,
    statetype: Optional[str] = None,
    floating: Optional[bool] = None,
    direction: Optional[str] = None,
    icmp_types: Optional[List[str]] = None,
) -> Optional[str]:
    """Validate documented FirewallRule choices before calling pfSense."""
    if rule_type is not None and rule_type not in _RULE_TYPES:
        return f"Invalid rule_type '{rule_type}'. Must be: {', '.join(sorted(_RULE_TYPES))}"
    if ip_protocol is not None and ip_protocol not in _IP_PROTOCOLS:
        return f"Invalid ip_protocol '{ip_protocol}'. Must be: {', '.join(sorted(_IP_PROTOCOLS))}"
    if protocol is not None and protocol.lower() not in _PROTOCOLS:
        return f"Invalid protocol '{protocol}'. Must be: {', '.join(sorted(_PROTOCOLS))}"
    if statetype is not None and statetype not in _STATE_TYPES:
        return f"Invalid statetype '{statetype}'. Must be: {', '.join(sorted(_STATE_TYPES))}"
    if direction is not None and direction not in _FLOATING_DIRECTIONS:
        return f"Invalid direction '{direction}'. Must be: {', '.join(sorted(_FLOATING_DIRECTIONS))}"
    if direction is not None and floating is False:
        return "direction only applies when floating=True"
    if icmp_types is not None and not all(isinstance(value, str) and value for value in icmp_types):
        return "icmp_types must be a list of non-empty ICMP type names"
    return None


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
async def search_firewall_rules(
    interface: Optional[str] = None,
    source_ip: Optional[str] = None,
    destination_port: Optional[Union[int, str]] = None,
    rule_type: Optional[str] = None,
    disabled: Optional[bool] = None,
    search_description: Optional[str] = None,
    page: int = 1,
    page_size: int = 20,
    sort_by: str = "tracker"
) -> Dict:
    """Search firewall rules with advanced filtering and pagination.

    Args:
        interface: Filter by interface (wan, lan, etc.)
        source_ip: Filter by source IP (supports partial matching)
        destination_port: Filter by destination port
        rule_type: Filter by rule type (pass, block, reject)
        disabled: Filter by enabled/disabled state (true = disabled rules only)
        search_description: Search in rule descriptions
        page: Page number for pagination
        page_size: Number of results per page (max 200)
        sort_by: Field to sort by (tracker, interface, type, descr, etc.)
    """
    client = get_api_client()
    try:
        filters = []

        if interface:
            filters.append(create_interface_filter(interface))

        if source_ip:
            filters.append(QueryFilter("source", source_ip, "contains"))

        if destination_port:
            filters.append(create_port_filter(destination_port))

        if rule_type:
            filters.append(QueryFilter("type", rule_type))

        if disabled is not None:
            filters.append(QueryFilter("disabled", disabled))

        if search_description:
            filters.append(QueryFilter("descr", search_description, "contains"))

        pagination, page, page_size = create_pagination(page, page_size)
        sort = create_default_sort(sort_by)

        rules = await client.get_firewall_rules(
            filters=filters if filters else None,
            sort=sort,
            pagination=pagination
        )

        return {
            "success": True,
            "page": page,
            "page_size": page_size,
            "filters_applied": {
                "interface": interface,
                "source_ip": source_ip,
                "destination_port": destination_port,
                "rule_type": rule_type,
                "disabled": disabled,
                "search_description": search_description,
            },
            "count": len(rules.get("data") or []),
            "rules": rules.get("data") or [],
            "links": client.extract_links(rules),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to search firewall rules: {e}")
        return {"success": False, "error": str(e)}


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
async def find_blocked_rules(
    interface: Optional[str] = None,
) -> Dict:
    """Find all firewall rules that block or reject traffic

    Args:
        interface: Optional interface filter (wan, lan, etc.)
    """
    client = get_api_client()
    try:
        rules = await client.find_blocked_rules()

        # Apply interface filter if specified
        # interface field is a list (e.g. ["wan"]), so use 'in' not '=='
        if interface:
            rules["data"] = [
                rule for rule in rules.get("data") or []
                if interface in (rule.get("interface") or [])
            ]

        return {
            "success": True,
            "interface_filter": interface,
            "count": len(rules.get("data") or []),
            "blocked_rules": rules.get("data") or [],
            "links": client.extract_links(rules),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to find blocked rules: {e}")
        return {"success": False, "error": str(e)}


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False))
@rate_limited
async def create_firewall_rule_advanced(
    interface: Union[str, List[str]],
    rule_type: str,
    protocol: str,
    source: str,
    destination: str,
    description: Optional[str] = None,
    source_port: Optional[str] = None,
    destination_port: Optional[str] = None,
    ip_protocol: str = "inet",
    icmp_types: Optional[List[str]] = None,
    dscp: Optional[str] = None,
    tag: Optional[str] = None,
    statetype: str = "keep state",
    tcp_flags_any: Optional[bool] = None,
    tcp_flags_out_of: Optional[List[str]] = None,
    tcp_flags_set: Optional[List[str]] = None,
    gateway: Optional[str] = None,
    schedule: Optional[str] = None,
    dnpipe: Optional[str] = None,
    pdnpipe: Optional[str] = None,
    default_queue: Optional[str] = None,
    ack_queue: Optional[str] = None,
    floating: bool = False,
    quick: Optional[bool] = None,
    direction: Optional[str] = None,
    position: Optional[int] = None,
    disabled: bool = False,
    apply_immediately: bool = True,
    log_matches: bool = True,
) -> Dict:
    """Create a firewall rule on the live pfSense appliance.

    WARNING: This modifies the running firewall configuration.

    Args:
        interface: Interface name or list of interface names. A list is required to target multiple interfaces in a Floating rule.
        rule_type: Rule type (pass, block, reject)
        protocol: IP/transport protocol (tcp, udp, tcp/udp, icmp, esp, ah, gre, ipv6, igmp, pim, ospf, carp, pfsync, any)
        source: Source address (any, IP, network, alias name)
        destination: Destination address (any, IP, network, alias name)
        description: Optional rule description
        source_port: Source port — single (443), range (1024-65535), or alias name
        destination_port: Destination port — single (443), range (1024-65535), or alias name
        ip_protocol: Address family: inet (IPv4), inet6 (IPv6), or inet46 (both)
        icmp_types: ICMP types to match; only applicable to IPv4 ICMP rules
        dscp: DSCP value to match
        tag: Packet tag to apply for use by other firewall/NAT rules
        statetype: State handling: keep state, sloppy state, synproxy state, or none
        tcp_flags_any: Whether to match any TCP flags
        tcp_flags_out_of: TCP flags allowed to be set when tcp_flags_any is false
        tcp_flags_set: TCP flags required to be set when tcp_flags_any is false
        gateway: Optional gateway for policy routing (e.g., "WAN_DHCP")
        schedule: Optional existing firewall schedule name
        dnpipe: Optional incoming limiter pipe or queue name
        pdnpipe: Optional outgoing limiter pipe or queue name
        default_queue: Optional traffic shaper default queue name
        ack_queue: Optional traffic shaper ACK queue name
        floating: Create a Floating rule. Requires direction; interface may contain multiple values.
        quick: For Floating rules, stop evaluation immediately on match. Defaults to true for Floating rules.
        direction: Floating rule direction: any, in, or out. Defaults to any for Floating rules.
        position: Position to insert rule (0 = top). Rule is created first, then moved.
        disabled: Create the rule in disabled state (useful for staging)
        apply_immediately: Whether to apply changes to the running firewall
        log_matches: Whether to log packets matching this rule
    """
    client = get_api_client()

    option_error = _validate_rule_options(
        rule_type=rule_type,
        ip_protocol=ip_protocol,
        protocol=protocol,
        statetype=statetype,
        floating=floating,
        direction=direction,
        icmp_types=icmp_types,
    )
    if option_error:
        return {"success": False, "error": option_error}
    if icmp_types is not None and (protocol.lower() != "icmp" or ip_protocol != "inet"):
        return {"success": False, "error": "icmp_types only applies to IPv4 ICMP rules"}

    # Validate port formats before sending to API
    for port_param, port_val in [("source_port", source_port), ("destination_port", destination_port)]:
        if port_val:
            port_error = validate_port_value(port_val, port_param)
            if port_error:
                return {"success": False, "error": port_error}

    try:
        interfaces = _normalize_interfaces(interface)
    except ValueError as exc:
        return {"success": False, "error": str(exc)}

    rule_data = {
        "interface": interfaces,
        "type": rule_type,
        "ipprotocol": ip_protocol,
        "source": source,
        "destination": destination,
        "descr": sanitize_description(description) if description else f"Created via MCP at {datetime.now(timezone.utc).isoformat()}",
        "log": log_matches,
        "statetype": statetype,
        "disabled": disabled,
        "floating": floating,
    }

    # Handle protocol field - try null for "any", otherwise use the specified protocol
    if protocol and protocol.lower() == "any":
        rule_data["protocol"] = None  # Try null for "any protocol"
    elif protocol:
        rule_data["protocol"] = protocol

    if source_port:
        rule_data["source_port"] = source_port
    if destination_port:
        rule_data["destination_port"] = destination_port

    optional_fields = {
        "icmptype": icmp_types,
        "dscp": dscp,
        "tag": tag,
        "tcp_flags_any": tcp_flags_any,
        "tcp_flags_out_of": tcp_flags_out_of,
        "tcp_flags_set": tcp_flags_set,
        "gateway": gateway,
        "sched": schedule,
        "dnpipe": dnpipe,
        "pdnpipe": pdnpipe,
        "defaultqueue": default_queue,
        "ackqueue": ack_queue,
    }
    rule_data.update({key: value for key, value in optional_fields.items() if value is not None})

    if floating:
        rule_data["quick"] = True if quick is None else quick
        rule_data["direction"] = direction or "any"
    elif quick is not None:
        return {"success": False, "error": "quick only applies when floating=True"}

    # Create rule without placement (placement on POST is unreliable);
    # we'll move it afterward if a position was requested
    control = ControlParameters(
        apply=apply_immediately if position is None else False,
    )

    try:
        result = await client.create_firewall_rule(rule_data, control)

        # If a specific position was requested, move the rule there
        if position is not None:
            new_rule_id = safe_data_dict(result).get("id")
            if new_rule_id is not None:
                try:
                    await client.move_firewall_rule(
                        new_rule_id, position, apply_immediately=False
                    )
                except Exception as move_err:
                    # Rollback: delete the rule we just created to avoid
                    # leaving it at the wrong position in the ruleset
                    try:
                        await client.delete_firewall_rule(new_rule_id, apply_immediately=False)
                        logger.error("Move to position %d failed; rule %d rolled back (deleted)", position, new_rule_id)
                        return {
                            "success": False,
                            "error": (
                                f"Rule was created (id={new_rule_id}) but move to position {position} failed. "
                                f"Rule has been deleted to prevent misconfiguration. Error: {move_err}"
                            ),
                        }
                    except Exception as del_err:
                        logger.error("Move failed and rollback delete also failed: %s", del_err)
                        return {
                            "success": False,
                            "error": (
                                f"Rule was created (id={new_rule_id}) but move to position {position} failed: {move_err}. "
                                f"Rollback deletion also failed: {del_err}. "
                                f"Manual cleanup required — delete rule {new_rule_id}."
                            ),
                        }
            else:
                logger.warning("Rule created but ID not returned — cannot move to position %d", position)
            # Apply after create+move (create was deferred above when position is set)
            if apply_immediately:
                await client.apply_firewall_changes()

        return {
            "success": True,
            "message": "Firewall rule created with advanced options",
            "rule": result.get("data", result),
            "applied_immediately": apply_immediately,
            "position": position,
            "links": client.extract_links(result),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to create advanced firewall rule: {e}")
        return {"success": False, "error": str(e)}


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True))
async def move_firewall_rule(
    rule_id: int,
    new_position: int,
    apply_immediately: bool = True
) -> Dict:
    """Move a firewall rule to a new position in the rule order

    Args:
        rule_id: Rule ID (array index from search_firewall_rules, e.g., 0, 1, 2...)
        new_position: New position (0 = top, higher numbers = lower priority)
        apply_immediately: Whether to apply changes immediately
    """
    client = get_api_client()
    try:
        result = await client.move_firewall_rule(
            rule_id, new_position, apply_immediately=False
        )

        # The PATCH ?apply=true doesn't reliably trigger filter_configure,
        # so explicitly apply to ensure the compiled ruleset is updated
        if apply_immediately:
            await client.apply_firewall_changes()

        return {
            "success": True,
            "message": f"Rule {rule_id} moved to position {new_position}",
            "rule_id": rule_id,
            "new_position": new_position,
            "applied": apply_immediately,
            "result": result.get("data", result),
            "links": client.extract_links(result),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to move firewall rule: {e}")
        return {"success": False, "error": str(e)}


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True))
@rate_limited
async def update_firewall_rule(
    rule_id: int,
    rule_type: Optional[str] = None,
    interface: Optional[Union[str, List[str]]] = None,
    ip_protocol: Optional[str] = None,
    protocol: Optional[str] = None,
    source: Optional[str] = None,
    destination: Optional[str] = None,
    source_port: Optional[str] = None,
    destination_port: Optional[str] = None,
    description: Optional[str] = None,
    disabled: Optional[bool] = None,
    log_matches: Optional[bool] = None,
    icmp_types: Optional[List[str]] = None,
    dscp: Optional[str] = None,
    tag: Optional[str] = None,
    statetype: Optional[str] = None,
    tcp_flags_any: Optional[bool] = None,
    tcp_flags_out_of: Optional[List[str]] = None,
    tcp_flags_set: Optional[List[str]] = None,
    gateway: Optional[str] = None,
    schedule: Optional[str] = None,
    dnpipe: Optional[str] = None,
    pdnpipe: Optional[str] = None,
    default_queue: Optional[str] = None,
    ack_queue: Optional[str] = None,
    floating: Optional[bool] = None,
    quick: Optional[bool] = None,
    direction: Optional[str] = None,
    clear_fields: Optional[List[str]] = None,
    apply_immediately: bool = True,
    verify_descr: Optional[str] = None,
) -> Dict:
    """Update an existing firewall rule by ID

    Args:
        rule_id: Rule ID (array index from search_firewall_rules, e.g., 0, 1, 2...)
        rule_type: Rule type (pass, block, reject)
        interface: Interface name or list of interface names
        ip_protocol: Address family: inet (IPv4), inet6 (IPv6), or inet46 (both)
        protocol: IP/transport protocol, or any
        source: Source address (any, IP, network, alias name)
        destination: Destination address (any, IP, network, alias name)
        source_port: Single port (443), range (1024-65535), or alias name
        destination_port: Single port (443), range (1024-65535), or alias name. Do NOT pass multiple space/comma-separated ports — create a port alias first instead.
        description: Rule description
        disabled: Whether the rule is disabled
        log_matches: Whether to log rule matches
        icmp_types: ICMP types to match; only applicable to IPv4 ICMP rules
        dscp: DSCP value to match
        tag: Packet tag to apply
        statetype: State handling: keep state, sloppy state, synproxy state, or none
        tcp_flags_any: Whether to match any TCP flags
        tcp_flags_out_of: TCP flags allowed to be set when tcp_flags_any is false
        tcp_flags_set: TCP flags required to be set when tcp_flags_any is false
        gateway: Gateway for policy routing
        schedule: Existing firewall schedule name
        dnpipe: Incoming limiter pipe or queue name
        pdnpipe: Outgoing limiter pipe or queue name
        default_queue: Traffic shaper default queue name
        ack_queue: Traffic shaper ACK queue name
        floating: Whether this is a Floating rule
        quick: For a Floating rule, stop evaluation immediately on match
        direction: Floating rule direction: any, in, or out
        clear_fields: Nullable fields to clear. Valid values: protocol, source_port, destination_port, dscp, gateway, schedule, dnpipe, pdnpipe, default_queue, ack_queue.
        apply_immediately: Whether to apply changes immediately
        verify_descr: Safety check — if provided, verifies the rule at this ID still has this description before updating. Prevents operating on the wrong rule after ID shifts.
    """
    client = get_api_client()
    try:
        # Stale-ID guard: verify the rule still matches before updating
        if verify_descr is not None:
            id_err = await client.verify_object_id("/firewall/rules", rule_id, "descr", verify_descr)
            if id_err:
                return {"success": False, "error": id_err}

        option_error = _validate_rule_options(
            rule_type=rule_type,
            ip_protocol=ip_protocol,
            protocol=protocol,
            statetype=statetype,
            floating=floating,
            direction=direction,
            icmp_types=icmp_types,
        )
        if option_error:
            return {"success": False, "error": option_error}

        if icmp_types is not None and (protocol is not None and protocol.lower() != "icmp"):
            return {"success": False, "error": "icmp_types requires protocol='icmp' when protocol is updated"}

        # Validate port formats before sending to API
        for port_param, port_val in [("source_port", source_port), ("destination_port", destination_port)]:
            if port_val:
                port_error = validate_port_value(port_val, port_param)
                if port_error:
                    return {"success": False, "error": port_error}

        # Map Python parameter names to pfSense API field names
        field_map = {
            "rule_type": "type",
            "interface": "interface",
            "ip_protocol": "ipprotocol",
            "protocol": "protocol",
            "source": "source",
            "destination": "destination",
            "source_port": "source_port",
            "destination_port": "destination_port",
            "description": "descr",
            "disabled": "disabled",
            "log_matches": "log",
            "icmp_types": "icmptype",
            "dscp": "dscp",
            "tag": "tag",
            "statetype": "statetype",
            "tcp_flags_any": "tcp_flags_any",
            "tcp_flags_out_of": "tcp_flags_out_of",
            "tcp_flags_set": "tcp_flags_set",
            "gateway": "gateway",
            "schedule": "sched",
            "dnpipe": "dnpipe",
            "pdnpipe": "pdnpipe",
            "default_queue": "defaultqueue",
            "ack_queue": "ackqueue",
            "floating": "floating",
            "quick": "quick",
            "direction": "direction",
        }

        params = {
            "rule_type": rule_type,
            "interface": interface,
            "ip_protocol": ip_protocol,
            "protocol": protocol,
            "source": source,
            "destination": destination,
            "source_port": source_port,
            "destination_port": destination_port,
            "description": description,
            "disabled": disabled,
            "log_matches": log_matches,
            "icmp_types": icmp_types,
            "dscp": dscp,
            "tag": tag,
            "statetype": statetype,
            "tcp_flags_any": tcp_flags_any,
            "tcp_flags_out_of": tcp_flags_out_of,
            "tcp_flags_set": tcp_flags_set,
            "gateway": gateway,
            "schedule": schedule,
            "dnpipe": dnpipe,
            "pdnpipe": pdnpipe,
            "default_queue": default_queue,
            "ack_queue": ack_queue,
            "floating": floating,
            "quick": quick,
            "direction": direction,
        }

        updates = {}
        for param_name, value in params.items():
            if value is not None:
                api_field = field_map[param_name]
                if param_name == "interface":
                    updates[api_field] = _normalize_interfaces(value)
                elif param_name == "protocol" and isinstance(value, str) and value.lower() == "any":
                    updates[api_field] = None
                else:
                    updates[api_field] = value

        clear_field_map = {
            "protocol": "protocol",
            "source_port": "source_port",
            "destination_port": "destination_port",
            "dscp": "dscp",
            "gateway": "gateway",
            "schedule": "sched",
            "dnpipe": "dnpipe",
            "pdnpipe": "pdnpipe",
            "default_queue": "defaultqueue",
            "ack_queue": "ackqueue",
        }
        if clear_fields:
            invalid_fields = set(clear_fields) - set(clear_field_map)
            if invalid_fields:
                return {"success": False, "error": f"Invalid clear_fields: {', '.join(sorted(invalid_fields))}"}
            for field in clear_fields:
                updates[clear_field_map[field]] = None

        if not updates:
            return {"success": False, "error": "No fields to update - provide at least one field"}

        control = ControlParameters(apply=apply_immediately)
        result = await client.update_firewall_rule(rule_id, updates, control)

        return {
            "success": True,
            "message": f"Firewall rule {rule_id} updated",
            "rule_id": rule_id,
            "fields_updated": list(updates.keys()),
            "applied": apply_immediately,
            "result": result.get("data", result),
            "links": client.extract_links(result),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to update firewall rule: {e}")
        return {"success": False, "error": str(e)}


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True))
@guarded
async def delete_firewall_rule(
    rule_id: int,
    apply_immediately: bool = True,
    confirm: bool = False,
    dry_run: bool = False,
    verify_descr: Optional[str] = None,
) -> Dict:
    """Delete a firewall rule from the live pfSense appliance. WARNING: This is irreversible.

    Args:
        rule_id: Rule ID (array index from search_firewall_rules, e.g., 0, 1, 2...)
        apply_immediately: Whether to apply changes immediately
        confirm: Must be set to True to execute. Safety gate for destructive operations.
        dry_run: If True, preview the operation without executing.
        verify_descr: Safety check — if provided, verifies the rule at this ID still has this description before deleting. Prevents deleting the wrong rule after ID shifts.
    """
    client = get_api_client()
    try:
        # Stale-ID guard: verify the rule still matches before deleting
        if verify_descr is not None:
            id_err = await client.verify_object_id("/firewall/rules", rule_id, "descr", verify_descr)
            if id_err:
                return {"success": False, "error": id_err}
        result = await client.delete_firewall_rule(rule_id, apply_immediately)

        return {
            "success": True,
            "message": f"Firewall rule {rule_id} deleted",
            "rule_id": rule_id,
            "applied": apply_immediately,
            "result": result.get("data", result),
            "links": client.extract_links(result),
            "note": "Object IDs have shifted after deletion. Re-query rules before performing further operations by ID.",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to delete firewall rule: {e}")
        return {"success": False, "error": str(e)}


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True))
@guarded
async def bulk_block_ips(
    ip_addresses: List[str],
    interface: str = "wan",
    description_prefix: str = "Bulk block via MCP",
    confirm: bool = False,
    dry_run: bool = False,
) -> Dict:
    """Block multiple IP addresses on the live pfSense firewall. WARNING: Creates block rules.

    Args:
        ip_addresses: List of IP addresses to block
        interface: Interface to apply blocks on
        description_prefix: Prefix for rule descriptions
        confirm: Must be set to True to execute. Safety gate for destructive operations.
        dry_run: If True, preview the operation without executing.
    """
    # Cap bulk operations to prevent overwhelming pfSense
    if len(ip_addresses) > MAX_BULK_IPS:
        return {
            "success": False,
            "error": f"Too many IPs ({len(ip_addresses)}). Maximum is {MAX_BULK_IPS} per call.",
        }

    client = get_api_client()
    results = []
    errors = []

    for ip in ip_addresses:
        # Validate IP/network before making API call
        try:
            validate_ip_address(ip)
        except ValueError:
            logger.error(f"Invalid IP address/network: {ip}")
            errors.append({"ip": ip, "error": f"Invalid IP address or network: {ip}"})
            continue

        try:
            rule_data = {
                "interface": [interface] if isinstance(interface, str) else interface,
                "type": "block",
                "ipprotocol": "inet",
                "protocol": None,  # null = any protocol
                "source": ip,
                "destination": "any",
                "descr": f"{description_prefix}: {ip}",
                "log": True,
                "statetype": "keep state",
            }

            # Don't apply immediately for bulk operations
            control = ControlParameters(apply=False)
            result = await client.create_firewall_rule(rule_data, control)
            results.append({"ip": ip, "success": True, "rule_id": safe_data_dict(result).get("id")})

        except Exception as e:
            logger.error(f"Failed to block IP {ip}: {e}")
            errors.append({"ip": ip, "error": str(e)})

    # Apply all changes at once
    warning = None
    if results:
        try:
            await client.apply_firewall_changes()
            applied = True
        except Exception as e:
            applied = False
            pending_ids = [r.get("rule_id") for r in results if r.get("rule_id") is not None]
            warning = (
                f"{len(results)} block rules were created but NOT applied to the running firewall. "
                f"Call apply_firewall_changes() to activate them, or delete them to undo. "
                f"Pending rule IDs: {pending_ids}. Apply error: {e}"
            )
            logger.error(f"Failed to apply bulk changes: {e}")
    else:
        applied = False

    response = {
        "success": len(results) > 0,
        "total_requested": len(ip_addresses),
        "successful": len(results),
        "failed": len(errors),
        "applied": applied,
        "results": results,
        "errors": errors,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    if warning:
        response["warning"] = warning
    return response


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True))
async def apply_firewall_changes() -> Dict:
    """Force apply pending firewall changes and recompile the pf ruleset.

    Use this after any firewall config change to ensure the compiled ruleset
    (/tmp/rules.debug) matches the configuration. The apply_immediately
    parameter on other tools doesn't always trigger full recompilation.
    """
    client = get_api_client()
    try:
        result = await client.apply_firewall_changes()

        return {
            "success": True,
            "message": "Firewall changes applied and filter ruleset recompiled",
            "result": result.get("data", result),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to apply firewall changes: {e}")
        return {"success": False, "error": str(e)}


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
async def get_pf_rules() -> Dict:
    """Read the compiled pf ruleset (/tmp/rules.debug) to verify what pf is
    actually enforcing vs what's in config.xml.

    Returns the raw compiled rules that the packet filter is using.
    """
    client = get_api_client()
    try:
        result = await client._run_diagnostic_command("cat /tmp/rules.debug")

        return {
            "success": True,
            "compiled_rules": result.get("data", result),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to read compiled rules: {e}")
        return {"success": False, "error": str(e)}
