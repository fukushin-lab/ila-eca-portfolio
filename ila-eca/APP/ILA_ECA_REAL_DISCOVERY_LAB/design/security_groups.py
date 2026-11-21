"""G-only AWS SG JSON attribute shapes, based on provider6.73.0 schema.

No rule/field/value is added. Does not select security policy, evaluate HCL,
run providers, or certify other provider versions/AWS semantics.
"""

from ILA_ECA_REAL_DISCOVERY_LAB.design import expressions as e

FIELDS = {
    'cidr_blocks': 'collection',
    'description': 'string',
    'from_port': 'number',
    'ipv6_cidr_blocks': 'collection',
    'prefix_list_ids': 'collection',
    'protocol': 'string',
    'security_groups': 'collection',
    'self': 'bool',
    'to_port': 'number',
}


def schema():
    def scalar(kinds):
        return {'anyOf': [{'type': kind} for kind in kinds]}

    props = {}
    for name, kind in FIELDS.items():
        if kind == 'collection':
            props[name] = {
                'anyOf': [
                    {'type': 'null'},
                    {'type': 'string'},
                    {'type': 'array', 'items': scalar(['string', 'number', 'boolean', 'null'])},
                ]
            }
        else:
            props[name] = scalar(
                {
                    'string': ['string', 'number', 'boolean', 'null'],
                    'number': ['number', 'string', 'null'],
                    'bool': ['boolean', 'string', 'null'],
                }[kind]
            )
    item = {
        'type': 'object',
        'properties': props,
        'required': sorted(FIELDS),
        'additionalProperties': False,
        'description': 'Complete provider6.73.0 SG attribute object. Emit unused optional fields explicitly as null or justified empty collections; never infer network permissions from this shape.',
    }
    return {
        'anyOf': [{'type': 'null'}, {'type': 'string'}, {'type': 'array', 'items': item}],
        'description': 'Optional attributes-as-blocks JSON collection, not native HCL nested-block omission rules. A single ${...} may return the complete typed collection. [] explicitly manages no rules; omission/null have different intent. Standalone SG rule resources are also allowed.',
    }


def assess(tf):
    checked = []
    unverified = []

    def fail(code, path):
        raise e.ContractError('AWS_DESIGN_SG_' + code, 'SPECIFICATION', path)

    def fits(t, kind, path):
        source = t['kind']
        if source == 'null':
            return
        if source == 'unknown':
            unverified.append(
                {'target': path, 'reason': 'Provider attribute value type not statically known'}
            )
            return
        if kind == 'collection':
            if source not in {'tuple', 'list', 'set'}:
                fail('ATTRIBUTE_TYPE_MISMATCH', path)
            members = t['items'] if source == 'tuple' else [t['element']]
            for member in members:
                fits(member, 'string', path)
        elif source == kind or (kind == 'string' and source in {'number', 'bool'}):
            return
        elif source == 'string' and kind in {'number', 'bool'}:
            unverified.append(
                {
                    'target': path,
                    'reason': 'String conversion to ' + kind + ' requires actual Terraform values',
                }
            )
        else:
            fail('ATTRIBUTE_TYPE_MISMATCH', path)

    for name, block in tf.get('resource', {}).get('aws_security_group', {}).items():
        for direction in ['ingress', 'egress']:
            if direction not in block:
                continue
            path = '/resource/aws_security_group/' + name + '/' + direction
            value = block[direction]
            if value is None:
                unverified.append(
                    {'target': path, 'reason': 'Null/unmanaged rule intent requires review'}
                )
                continue
            if type(value) is str:
                parts = e.template_parts(value)
                if len(parts) != 1 or parts[0][0] != 'expression':
                    raise e.ContractError(
                        'AWS_DESIGN_SG_COLLECTION_EXPRESSION_REQUIRED', 'FORMAT', path
                    )
            result = e.check(tf, value, path=path)
            t = result['result_type']
            kind = t['kind']
            unverified.extend({'target': path, 'reason': reason} for reason in result['unverified'])
            if kind == 'unknown':
                unverified.append(
                    {
                        'target': path,
                        'reason': 'SG object members cannot be checked; not certified complete',
                    }
                )
                continue
            if kind not in {'tuple', 'list', 'set'}:
                fail('RULE_COLLECTION_TYPE_MISMATCH', path)
            members = t['items'] if kind == 'tuple' else [t['element']]
            for index, member in enumerate(members):
                target = path + '/' + str(index)
                if member['kind'] == 'unknown':
                    unverified.append(
                        {'target': target, 'reason': 'SG object member shape is unknown'}
                    )
                    continue
                if member['kind'] != 'object':
                    fail('RULE_OBJECT_REQUIRED', target)
                attrs = member['attrs']
                if set(attrs) != set(FIELDS):
                    fail('RULE_FIELDS_INCOMPLETE_OR_UNKNOWN', target)
                for field, expected in FIELDS.items():
                    fits(attrs[field], expected, target + '/' + field)
            checked.append(
                {
                    'target': path,
                    'scope': 'Complete object attributes and known convertible types only',
                }
            )
    return {
        'basis': 'hashicorp/aws6.73.0 / Terraform1.17.2 recorded provider schema',
        'checked_inline_fields': checked,
        'unverified': unverified,
        'configuration_added': False,
        'scope': 'Only aws_security_group ingress/egress JSON shape; no rule/policy/resource defaults, no other AWS constraints or provider version guarantee',
        'terraform_execution': 'NOT_RUN',
    }
