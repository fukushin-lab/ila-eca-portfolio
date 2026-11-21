"""G-only input-rule inspection. Never evaluates HCL or adds configuration.

Recognized predicates are compared as parsed syntax, not as regex matches on
condition text. Other legitimate predicates remain NOT_VERIFIED, not invalid
Terraform. Coverage is the three supported input relationships, not all AWS.
"""

import itertools
import json
from ILA_ECA_REAL_DISCOVERY_LAB.design import expressions as e

VERSION = 'ila.g.input-validation-contract.v2'
INSPECTION_REVISION = 'format-and-sg-shapes.1'
SECRET_PATTERN = '^arn:aws:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret[:][A-Za-z0-9/_+=.@-]{1,512}-[A-Za-z0-9]{6}$'


def fail(code, category='SPECIFICATION', path=''):
    raise e.ContractError('AWS_DESIGN_INPUT_' + code, category, path)


def expression(text):
    if type(text) is not str or not text.strip():
        fail('VALIDATION_CONDITION_REQUIRED', 'FORMAT')
    parts = e.template_parts(text)
    if len(parts) != 1 or parts[0][0] != 'expression':
        fail('VALIDATION_BOOLEAN_EXPRESSION_REQUIRED', 'FORMAT')
    try:
        return e.parse(parts[0][1])
    except ImportError:
        fail('VALIDATION_PARSER_UNAVAILABLE', 'NOT_VERIFIED')
    except e.ContractError:
        raise
    except Exception:
        fail('VALIDATION_EXPRESSION_NOT_PARSED', 'NOT_VERIFIED')


def refpath(node):
    node = e.unwrap(node)
    c = e.kids(node)
    if e.tag(node) == 'identifier':
        return [e.ident(node)]
    if e.tag(node) == 'get_attr_expr_term':
        head = refpath(c[0])
        return head + [e.ident(e.kids(c[1])[0])] if head else None
    return None


def canonical(node, tf, scope=None, active=()):
    scope = scope or {}
    node = e.unwrap(node)
    path = refpath(node)
    if path and path[0] == 'local' and len(path) == 2:
        if path[1] in active:
            fail('VALIDATION_LOCAL_CYCLE')
        value = tf.get('locals', {}).get(path[1])
        if value is None:
            fail('VALIDATION_LOCAL_UNDECLARED')
        return canonical(expression(value), tf, scope, active + (path[1],))
    if e.tag(node) == 'identifier':
        return ('identifier', scope.get(e.ident(node), e.ident(node)))
    # The parser may nest an unparenthesized ternary inside a binary chain,
    # although Terraform gives the ternary lower precedence. Do not derive
    # implication from that ambiguous shape; conditional predicates need review.
    if e.tag(node) == 'conditional':
        fail('BOOLEAN_CONDITIONAL_NOT_VERIFIED', 'NOT_VERIFIED')
    if e.tag(node) == 'binary_op':
        # python-hcl2 represents an unparenthesized operator chain as a
        # right-nested tree. Rebuild it using HCL precedence; do not mistake
        # `a != b || true` for a required inequality, or flatten parentheses.
        precedence = {
            '||': 1,
            '&&': 2,
            '==': 3,
            '!=': 3,
            '<': 4,
            '<=': 4,
            '>': 4,
            '>=': 4,
            '+': 5,
            '-': 5,
            '*': 6,
            '/': 6,
            '%': 6,
        }
        values = []
        operators = []

        def reduce():
            right = values.pop()
            left = values.pop()
            values.append(('binary', operators.pop(), left, right))

        while e.tag(node) == 'binary_op':
            c = e.kids(node)
            if len(c) != 2 or e.tag(c[1]) != 'binary_term':
                fail('BOOLEAN_SHAPE_NOT_VERIFIED', 'NOT_VERIFIED')
            term = e.kids(c[1])
            op = e.ident(term[0])
            if op not in precedence:
                fail('BOOLEAN_OPERATOR_NOT_VERIFIED', 'NOT_VERIFIED')
            values.append(canonical(c[0], tf, scope, active))
            while operators and precedence[operators[-1]] >= precedence[op]:
                reduce()
            operators.append(op)
            node = term[1]
        values.append(canonical(node, tf, scope, active))
        while operators:
            reduce()
        return values[0]
    if e.tag(node) == 'function_call':
        c = e.kids(node)
        return (
            'call',
            e.ident(c[0]),
            tuple(canonical(x, tf, scope, active) for x in (e.kids(c[1]) if len(c) > 1 else [])),
        )
    if e.tag(node) == 'object':
        pairs = list(e.object_items(node))
        if all(type(k) is str for k, v in pairs):
            return ('object', tuple(sorted((k, canonical(v, tf, scope, active)) for k, v in pairs)))
    if e.tag(node) in {'for_tuple_expr', 'for_object_expr'}:
        c = e.kids(node)
        intro = c[0]
        names = [e.ident(x) for x in e.kids(intro) if e.tag(x) == 'identifier']
        bound = {**scope, **{name: 'bound_' + str(i) for i, name in enumerate(names)}}
        return (
            e.tag(node),
            len(names),
            canonical(e.kids(intro)[-1], tf, scope, active),
            tuple(canonical(x, tf, bound, active) for x in c[1:]),
        )
    if hasattr(node, 'data'):
        return (
            e.tag(node),
            tuple(
                canonical(x, tf, scope, active) if hasattr(x, 'data') else str(x)
                for x in node.children
            ),
        )
    return str(node)


def conjuncts(node):
    if node[:2] == ('binary', '&&'):
        return conjuncts(node[2]) + conjuncts(node[3])
    return [node]


def matches(rule, templates, tf):
    current = canonical(rule['tree'], tf)
    parts = conjuncts(current)
    for text in templates:
        needed = conjuncts(canonical(e.parse(text), tf))
        if not all(item in parts for item in needed):
            continue
        extras = [item for item in parts if item not in needed]
        # Extra constraints may strengthen the required predicate. They are
        # not certified by matching it. Unknown/effectful calls still HOLD;
        # never execute a condition or accept an arbitrary expression as proof.
        pure = {
            'trimspace',
            'length',
            'keys',
            'values',
            'toset',
            'tolist',
            'distinct',
            'setintersection',
            'alltrue',
            'can',
            'regex',
            'try',
            'split',
            'contains',
            'startswith',
            'strcontains',
            'floor',
            'lower',
            'upper',
            'format',
        }

        def safe(value):
            if not isinstance(value, tuple):
                return True
            return not (value[:1] == ('call',) and value[1] not in pure) and all(
                safe(x) for x in value
            )

        if all(safe(item) for item in extras):
            return {'additional_conjuncts': len(extras)}
    return None


def direct_refs(tf, value):
    """Use existing lexical scope handling, but keep local edges unexpanded."""

    class Direct(e.Inspector):
        def reference(self, path, scope):
            if path[0] == 'local' and path[0] not in scope and len(path) >= 2:
                if path[1] not in self.tf.get('locals', {}):
                    self.issue('AWS_DESIGN_LOCAL_UNDECLARED')
                self.refs.add('local.' + path[1])
                return e.ANY
            return super().reference(path, scope)

    inspector = Direct(tf)
    inspector.value(value, {})
    return inspector.refs


def dependency_check(tf, rules):
    """Check validation/variable/local dependency cycles, not a provider plan."""
    graph = {'var.' + name: set() for name in tf.get('variable', {})}
    paths = {}
    for rule in rules:
        owner = 'var.' + rule['owner']
        paths[owner] = rule['path']
        for value in [rule['condition'], rule['error_message']]:
            graph[owner].update(direct_refs(tf, value) - {owner})
    visited = set()
    active = []

    def visit(node):
        if node in active:
            fail(
                'VALIDATION_DEPENDENCY_CYCLE',
                'SPECIFICATION',
                paths.get(node, '/locals/' + node.split('.', 1)[1]),
            )
        if node in visited:
            return
        active.append(node)
        if node.startswith('local.'):
            graph[node] = set(direct_refs(tf, tf['locals'][node.split('.', 1)[1]]))
        for other in sorted(graph.get(node, ())):
            if not other.startswith(('var.', 'local.')):
                fail(
                    'VALIDATION_DEPENDENCIES_NOT_VERIFIED',
                    'NOT_VERIFIED',
                    paths.get(node, '/locals/' + node.split('.', 1)[1]),
                )
            visit(other)
        active.pop()
        visited.add(node)

    for rule in rules:
        visit('var.' + rule['owner'])
    return {
        'status': 'CHECKED_WITH_LIMITATIONS',
        'edges': {n: sorted(v) for n, v in sorted(graph.items())},
        'scope': 'Validation conditions and error messages through declared variables/locals. Direct owning-input references are allowed. Provider/resource/data dependencies remain unverified; not a complete Terraform graph check.',
    }


def vars_in(tf, value, path=''):
    # Existing syntax/reference inspector follows locals and iterator scope.
    r = e.check(tf, value, path=path)
    if any('parser unavailable' in s for s in r['unverified']):
        fail('VALIDATION_PARSER_UNAVAILABLE', 'NOT_VERIFIED')
    return {x[4:] for x in r['references'] if x.startswith('var.')}


def nodes_in(tf, value, active=()):
    """Visit object members in a JSON value/expression, expanding local aliases."""
    if type(value) is dict:
        if 'name' in value and any(k in value for k in ('environment', 'secrets')):
            yield '__container__', list(value.items())
        for key, v in value.items():
            yield key, v
            yield from nodes_in(tf, v, active)
    elif type(value) is list:
        for v in value:
            yield from nodes_in(tf, v, active)
    elif type(value) is str:
        parts = e.template_parts(value)
        if not any(k == 'expression' for k, _ in parts):
            try:
                decoded = json.loads(value)
            except ValueError:
                return
            if isinstance(decoded, (dict, list)):
                yield from nodes_in(tf, decoded, active)
            return
        for kind, text in parts:
            if kind == 'expression':
                try:
                    node = e.parse(text)
                except ImportError:
                    fail('VALIDATION_PARSER_UNAVAILABLE', 'NOT_VERIFIED')
                except Exception:
                    fail('CONTAINER_EXPRESSION_NOT_PARSED', 'NOT_VERIFIED')
                yield from ast_nodes(tf, node, active)


def ast_nodes(tf, node, active=()):
    path = refpath(node)
    if path and path[0] == 'local' and len(path) == 2:
        if path[1] in active:
            fail('VALIDATION_LOCAL_CYCLE')
        yield from nodes_in(tf, tf.get('locals', {}).get(path[1]), active + (path[1],))
        return
    if e.tag(node) == 'object':
        fields = list(e.object_items(node))
        if any(k == 'name' for k, v in fields) and any(
            k in {'environment', 'secrets'} for k, v in fields
        ):
            yield '__container__', fields
        if {'Action', 'Resource'} <= {k for k, v in fields}:
            yield '__policy_statement__', fields
        for key, value in fields:
            yield key, value
    for child in e.kids(node):
        yield from ast_nodes(tf, child, active)


def ast_vars(tf, node):
    names = set()
    for x in node.iter_subtrees():
        path = refpath(x)
        if path and path[0] == 'var' and len(path) >= 2:
            names.add(path[1])
        elif path and path[0] == 'local' and len(path) == 2:
            names.update(vars_in(tf, tf.get('locals', {}).get(path[1])))
    return names


def field_vars(tf, value):
    return ast_vars(tf, value) if hasattr(value, 'data') else vars_in(tf, value)


def map_keys_preserved(tf, value, name, member):
    node = value if hasattr(value, 'data') else expression(value)
    template = e.parse(f'[for key, entry in var.{name} : {{name=key, {member}=entry}}]')
    return canonical(node, tf) == canonical(template, tf)


def literal_strings(value):
    if hasattr(value, 'data'):
        node = e.unwrap(value)
        if e.tag(node) == 'tuple':
            result = [e.literal(x) for x in e.kids(node)]
            return result if all(type(x) is str for x in result) else None
        item = e.literal(node)
        return [item] if type(item) is str else None
    if type(value) is str and '${' not in value:
        return [value]
    if type(value) is list and all(type(x) is str and '${' not in x for x in value):
        return value
    return None


def literal_names(value):
    if hasattr(value, 'data'):
        node = e.unwrap(value)
        if e.tag(node) != 'tuple':
            return None
        objects = e.kids(node)
        result = []
        for obj in objects:
            if e.tag(e.unwrap(obj)) != 'object':
                return None
            name = dict(e.object_items(e.unwrap(obj))).get('name')
            if name is None or type(e.literal(name)) is not str:
                return None
            result.append(e.literal(name))
        return result
    if type(value) is list and all(type(x) is dict and type(x.get('name')) is str for x in value):
        return [x['name'] for x in value]
    return None


def assess(tf):
    variables = tf.get('variable', {})
    rules = []
    unverified = []
    required = []
    satisfied = []
    for name, decl in variables.items():
        path = '/variable/' + name + '/validation'
        if 'validation' in decl and (
            type(decl['validation']) is not list or not decl['validation']
        ):
            fail('VALIDATION_RULES_INVALID', 'FORMAT', path)
        for i, rule in enumerate(decl.get('validation', [])):
            if (
                type(rule) is not dict
                or set(rule) != {'condition', 'error_message'}
                or type(rule['error_message']) is not str
                or not rule['error_message'].strip()
            ):
                fail('VALIDATION_RULE_INVALID', 'FORMAT', path + '/' + str(i))
            node = expression(rule['condition'])
            r = e.check(tf, rule['condition'])
            if 'var.' + name not in direct_refs(tf, rule['condition']):
                fail('VALIDATION_OWNER_NOT_REFERENCED', 'SPECIFICATION', path + '/' + str(i))
            if e.tag(e.unwrap(node)) == 'identifier' and e.ident(e.unwrap(node)) in {
                'true',
                'false',
            }:
                fail('VALIDATION_CONSTANT_CONDITION', 'SPECIFICATION', path + '/' + str(i))
            rules.append(
                {
                    'owner': name,
                    'path': path + '/' + str(i),
                    'tree': node,
                    'condition': rule['condition'],
                    'error_message': rule['error_message'],
                    'references': r['references'],
                }
            )
    dependencies = dependency_check(tf, rules)

    def require(kind, names, templates, path, nullable=None):
        names = set(names)
        nullable = set(nullable if nullable is not None else names)
        item = {'relationship': kind, 'inputs': sorted(names), 'target': path}
        required.append(item)
        for name in nullable:
            if variables.get(name, {}).get('nullable') is not False:
                fail('NON_NULL_REQUIRED', 'SPECIFICATION', '/variable/' + name)
        candidates = [
            r
            for r in rules
            if r['owner'] in names and {'var.' + n for n in names} <= set(r['references'])
        ]
        if not candidates:
            fail('VALIDATION_REQUIRED', 'SPECIFICATION', path)
        matching = [r for r in candidates if matches(r, templates, tf) is not None]
        if not matching:
            fail('PREDICATE_NOT_VERIFIED', 'NOT_VERIFIED', path)
        satisfied.append(
            {
                **item,
                'rule_paths': [r['path'] for r in matching],
                'semantics': 'REQUIRED_PREDICATE_ENTAILED_BY_TOP_LEVEL_CONJUNCTS_NOT_ALL_TERRAFORM',
            }
        )
        for rule in matching:
            if matches(rule, templates, tf)['additional_conjuncts']:
                unverified.append(
                    {
                        'target': rule['path'],
                        'reason': 'Required predicate is entailed; additional conjunct meaning and normal-input acceptance require separate review/testing',
                    }
                )

    # Follow ALB subnet references; choose no VPC, subnet count or AZ values.
    for resource_type in ['aws_lb', 'aws_alb']:
        for name, block in tf.get('resource', {}).get(resource_type, {}).items():
            path = '/resource/' + resource_type + '/' + name + '/subnets'
            subnets = block.get('subnets')
            kind = block.get('load_balancer_type', 'application')
            if kind in {'network', 'gateway'}:
                continue
            if kind != 'application':
                unverified.append(
                    {
                        'target': path,
                        'reason': 'Dynamic load-balancer type applicability requires review',
                    }
                )
                continue
            if subnets is None:
                unverified.append(
                    {
                        'target': path,
                        'reason': 'Subnet selection/availability-zone metadata is unavailable',
                    }
                )
                continue
            r = e.check(tf, subnets)
            az = set()
            known = []
            seen = False
            for ref in r['references']:
                if ref.startswith('aws_subnet.') and ref.split('.', 1)[1] in tf.get(
                    'resource', {}
                ).get('aws_subnet', {}):
                    seen = True
                    subnet = tf['resource']['aws_subnet'][ref.split('.', 1)[1]]
                    if 'availability_zone' in subnet:
                        value = subnet['availability_zone']
                        az.update(
                            vars_in(
                                tf,
                                value,
                                '/resource/aws_subnet/'
                                + ref.split('.', 1)[1]
                                + '/availability_zone',
                            )
                        )
                        if type(value) is str and '${' not in value:
                            known.append(value)
                    else:
                        unverified.append(
                            {'target': path, 'reason': 'Referenced subnet AZ is not explicit'}
                        )
            if az and all(
                e.declaration_type(variables[n].get('type'))['kind'] == 'string' for n in az
            ):
                if len(az) + len(set(known)) < 2:
                    fail('DISTINCT_AZS_NOT_ESTABLISHED', 'SPECIFICATION', path)
                for a, b in itertools.combinations(sorted(az), 2):
                    require(
                        'distinct availability zones',
                        {a, b},
                        [
                            f'var.{a} != var.{b}',
                            f'var.{b} != var.{a}',
                            f'!(var.{a} == var.{b})',
                            f'length(distinct([var.{a}, var.{b}])) == 2',
                        ],
                        path,
                    )
                for a in az:
                    for value in set(known):
                        require(
                            'distinct availability zones',
                            {a},
                            [f'var.{a} != {json.dumps(value)}', f'{json.dumps(value)} != var.{a}'],
                            path,
                        )
            elif len(az) == 1:
                a = next(iter(az))
                kind = e.declaration_type(variables[a].get('type'))['kind']
                if kind in {'map', 'list', 'set'} and e.declaration_type(
                    variables[a].get('type')
                ).get('element') == e.typ('string'):
                    values = f'values(var.{a})' if kind == 'map' else f'tolist(var.{a})'
                    require(
                        'distinct availability zones',
                        az,
                        [f'length(var.{a}) >= 2 && length(distinct({values})) == length(var.{a})'],
                        path,
                    )
                else:
                    fail('AZ_COLLECTION_MEMBERS_NOT_VERIFIED', 'NOT_VERIFIED', path)
            elif known and len(set(known)) < 2:
                fail('DISTINCT_AZS_NOT_ESTABLISHED', 'SPECIFICATION', path)
            elif az or not seen:
                unverified.append(
                    {
                        'target': path,
                        'reason': 'External subnet IDs, collection selection or AZ relationship requires review',
                    }
                )
    # Identify map inputs from the emitted container fields, not variable names.
    for name, block in tf.get('resource', {}).get('aws_ecs_task_definition', {}).items():
        path = '/resource/aws_ecs_task_definition/' + name + '/container_definitions'
        if 'container_definitions' not in block:
            continue
        groups = [
            v for k, v in nodes_in(tf, block['container_definitions']) if k == '__container__'
        ]
        if not groups:
            unverified.append(
                {'target': path, 'reason': 'Container members are not statically visible'}
            )
        for fields in groups:
            _assess_container(tf, variables, rules, unverified, require, path, block, fields)
    matched_paths = {p for item in satisfied for p in item['rule_paths']}
    for rule in rules:
        if rule['path'] not in matched_paths:
            unverified.append(
                {
                    'target': rule['path'],
                    'reason': 'Syntax/references checked; predicate meaning is not certified',
                }
            )
    return {
        'contract_version': VERSION,
        'inspection_revision': INSPECTION_REVISION,
        'validation_dependencies': dependencies,
        'required_relationships': required,
        'checked_relationships': satisfied,
        'unverified': unverified,
        'variable_rule_count': len(rules),
        'scope': 'Supported ALB AZ, ECS map-key separation, same-region commercial-AWS Secrets Manager inputs; not all AWS constraints',
        'terraform_execution': 'NOT_RUN',
        'configuration_added': False,
    }


def _assess_container(tf, variables, rules, unverified, require, path, block, fields):
    plain = set()
    secret = set()
    raw = {k: v for k, v in fields}
    for key, value in fields:
        if key == 'environment':
            plain.update(field_vars(tf, value))
        if key == 'secrets':
            secret.update(field_vars(tf, value))
    # Map-input rules certify actual container names/ARN values only when
    # the emitted transformation preserves those map keys and members.
    for names, key, member in [(plain, 'environment', 'value'), (secret, 'secrets', 'valueFrom')]:
        if names and (
            len(names) != 1 or not map_keys_preserved(tf, raw[key], next(iter(names)), member)
        ):
            fail('CONTAINER_INPUT_MAPPING_NOT_VERIFIED', 'NOT_VERIFIED', path)
    plain_literal = literal_names(raw['environment']) if 'environment' in raw else []
    secret_literal = literal_names(raw['secrets']) if 'secrets' in raw else []
    if (
        plain_literal is not None
        and secret_literal is not None
        and set(plain_literal) & set(secret_literal)
    ):
        fail('ENV_SECRET_LITERAL_NAMES_OVERLAP', 'SPECIFICATION', path)
    for dynamic, fixed in [(plain, secret_literal), (secret, plain_literal)]:
        if dynamic and fixed:
            name = next(iter(dynamic))
            fixed_names = json.dumps(sorted(set(fixed)))
            require(
                'disjoint dynamic and literal container names',
                {name},
                [f'length(setintersection(toset(keys(var.{name})), toset({fixed_names}))) == 0'],
                path,
            )
    if plain and secret:
        runtime = block.get('runtime_platform', [])
        runtime = runtime if type(runtime) is list else [runtime]
        if len(runtime) != 1 or runtime[0].get('operating_system_family') != 'LINUX':
            fail('OS_NAME_COMPARISON_NOT_VERIFIED', 'NOT_VERIFIED', path)
        if len(plain) == len(secret) == 1:
            a = next(iter(plain))
            b = next(iter(secret))
            if a == b:
                fail('ENV_SECRET_SOURCE_OVERLAP', 'SPECIFICATION', path)
            if all(e.declaration_type(variables[n].get('type'))['kind'] == 'map' for n in (a, b)):
                templates = []
                for left, right in [(a, b), (b, a)]:
                    templates += [
                        f'length(setintersection(toset(keys(var.{left})), toset(keys(var.{right})))) == 0',
                        f'length(setintersection(keys(var.{left}), keys(var.{right}))) == 0',
                    ]
                require('disjoint environment and secret names', {a, b}, templates, path)
            else:
                unverified.append(
                    {
                        'target': path,
                        'reason': 'Environment/secret collection member names are not map keys',
                    }
                )
        else:
            unverified.append(
                {
                    'target': path,
                    'reason': 'Multiple input maps/collection transformations need predicate review',
                }
            )
    for secret_var in secret:
        linked = []
        for policy in tf.get('resource', {}).get('aws_iam_role_policy', {}).values():
            p = policy.get('policy')
            if p:
                for key, fields in nodes_in(tf, p):
                    if key != '__policy_statement__':
                        continue
                    statement = dict(fields)
                    actions = literal_strings(statement['Action'])
                    if (
                        actions
                        and 'secretsmanager:GetSecretValue' in actions
                        and secret_var in field_vars(tf, statement['Resource'])
                    ):
                        linked.append(p)
        if not linked:
            unverified.append(
                {
                    'target': path,
                    'reason': 'Secret reference service/input contract is not established; no Secrets Manager choice is forced',
                }
            )
            continue
        if e.declaration_type(variables[secret_var].get('type')) != e.typ(
            'map', element=e.typ('string')
        ):
            fail('SECRET_REFERENCE_MAP_TYPE_NOT_VERIFIED', 'NOT_VERIFIED', path)
        providers = tf.get('provider', {}).get('aws', {})
        providers = providers if type(providers) is list else [providers]
        selected = block.get('provider', 'aws')
        alias = (
            selected.split('.', 1)[1]
            if type(selected) is str and selected.startswith('aws.')
            else None
        )
        providers = [p for p in providers if p.get('alias') == alias]
        if len(providers) != 1 or 'region' not in providers[0]:
            unverified.append(
                {
                    'target': path,
                    'reason': 'Provider region/alias or literal-region ARN relation requires review',
                }
            )
            continue
        region_value = providers[0]['region']
        if type(region_value) is not str:
            fail('PROVIDER_REGION_TYPE_INVALID', 'SPECIFICATION', path)
        regions = vars_in(tf, region_value)
        parts = e.template_parts(region_value)
        if len(parts) == 1 and parts[0][0] == 'expression':
            region_expr = parts[0][1]
        elif type(region_value) is str and '${' not in region_value:
            region_expr = json.dumps(region_value)
        else:
            unverified.append(
                {'target': path, 'reason': 'Provider region expression requires review'}
            )
            continue
        predicates = [
            f'alltrue([for item in values(var.{secret_var}) : can(regex({json.dumps(pattern)}, item)) && try(split(":", item)[3] == {region_expr}, false)])'
            for pattern in [SECRET_PATTERN, SECRET_PATTERN.replace('secret[:]', 'secret:')]
        ]
        require(
            'full same-region Secrets Manager ARN',
            {secret_var, *regions},
            predicates,
            path,
            nullable={secret_var},
        )
