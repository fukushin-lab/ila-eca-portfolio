"""G-only, non-executing HCL syntax/reference and bounded type checks.

This does not evaluate Terraform, call providers, read expression-named files,
or certify AWS arguments. Unknown semantics are recorded for review.
"""

from functools import lru_cache
import json
import math
import re


class ContractError(ValueError):
    def __init__(self, code, category='SPECIFICATION', path=''):
        super().__init__(code)
        self.category = category
        self.path = path


def shape(value, definition, path=''):
    if 'anyOf' in definition:
        for branch in definition['anyOf']:
            try:
                shape(value, branch, path)
                break
            except ContractError:
                continue
        else:
            raise ContractError('AWS_DESIGN_SCHEMA_TYPE_INVALID', 'FORMAT', path)
    kind = definition.get('type')
    ok = {
        'object': lambda: type(value) is dict,
        'array': lambda: type(value) is list,
        'string': lambda: type(value) is str,
        'boolean': lambda: type(value) is bool,
        'number': lambda: type(value) in (int, float) and math.isfinite(value),
        'null': lambda: value is None,
    }
    if kind in ok and not ok[kind]():
        raise ContractError('AWS_DESIGN_SCHEMA_TYPE_INVALID', 'FORMAT', path)
    if 'enum' in definition and value not in definition['enum']:
        raise ContractError('AWS_DESIGN_SCHEMA_ENUM_INVALID', 'FORMAT', path)
    if isinstance(value, dict):
        if any(type(k) is not str for k in value):
            raise ContractError('AWS_DESIGN_JSON_KEY_INVALID', 'FORMAT', path)
        props = definition.get('properties', {})
        if set(definition.get('required', [])) - set(value):
            raise ContractError('AWS_DESIGN_FIELDS_INVALID', 'FORMAT', path)
        if definition.get('additionalProperties') is False and set(value) - set(props):
            raise ContractError('AWS_DESIGN_FIELDS_INVALID', 'FORMAT', path)
        if len(value) < definition.get('minProperties', 0):
            raise ContractError('AWS_DESIGN_SCHEMA_OBJECT_EMPTY', 'FORMAT', path)
        extra = definition.get('additionalProperties', {})
        for k, v in value.items():
            shape(
                v,
                props.get(k, extra if isinstance(extra, dict) else {}),
                path + '/' + k.replace('~', '~0').replace('/', '~1'),
            )
    elif isinstance(value, list):
        for i, v in enumerate(value):
            shape(v, definition.get('items', {}), path + '/' + str(i))
    elif not (value is None or type(value) in (str, int, bool, float)) or (
        type(value) is float and not math.isfinite(value)
    ):
        raise ContractError('AWS_DESIGN_JSON_VALUE_INVALID', 'FORMAT', path)


ANY = {'kind': 'unknown'}


def typ(kind, **kw):
    return {'kind': kind, **kw}


def has_unknown_type(value):
    if isinstance(value, dict):
        return value.get('kind') == 'unknown' or any(has_unknown_type(x) for x in value.values())
    if isinstance(value, list):
        return any(has_unknown_type(x) for x in value)
    return False


def kids(n):
    return [x for x in getattr(n, 'children', []) if hasattr(x, 'data')]


def tag(n):
    return str(getattr(n, 'data', ''))


def unwrap(n):
    while tag(n) == 'expr_term' and len(kids(n)) == 1:
        n = kids(n)[0]
    return n


def ident(n):
    return str(n.children[0])


def literal(n):
    n = unwrap(n)
    if tag(n) == 'string' and not any(tag(x) == 'interpolation' for x in n.iter_subtrees()):
        return ''.join(str(y) for x in n.children for y in getattr(x, 'children', []))
    if tag(n) == 'int_lit':
        return int(''.join(map(str, n.children)))
    return None


@lru_cache(maxsize=256)
def parse(expression):
    import hcl2

    tree = hcl2.parses('g_value = ' + expression)
    body = kids(tree)[0]
    attributes = kids(body)
    if len(attributes) != 1 or tag(attributes[0]) != 'attribute':
        raise ContractError('AWS_DESIGN_EXPRESSION_SHAPE_INVALID', 'FORMAT')
    return kids(attributes[0])[-1]


def declaration_type(text):
    if text is None:
        return ANY
    # Terraform JSON permits the native type-constraint notation as a string.
    if not isinstance(text, str):
        return ANY
    if text in {'string', 'number', 'bool'}:
        return typ(text)
    try:
        return type_tree(parse(text))
    except (ImportError, ContractError):
        return ANY
    except Exception:
        return ANY


def type_tree(n):
    n = unwrap(n)
    t = tag(n)
    if t == 'identifier':
        return typ(ident(n)) if ident(n) in {'string', 'number', 'bool'} else ANY
    if t == 'function_call':
        c = kids(n)
        name = ident(c[0])
        args = kids(c[1]) if len(c) > 1 else []
        if name in {'list', 'set', 'map'} and len(args) == 1:
            return typ(name, element=type_tree(args[0]))
        if name == 'optional' and args:
            return type_tree(args[0])
        if name == 'object' and args:
            return typ(
                'object', attrs={key: type_tree(val) for key, val in object_items(unwrap(args[0]))}
            )
        if name == 'tuple' and args:
            return typ('tuple', items=[type_tree(x) for x in kids(unwrap(args[0]))])
    return ANY


def object_items(n):
    for item in kids(n):
        if tag(item) != 'object_elem':
            continue
        c = kids(item)
        keynode = kids(c[0])[0] if kids(c[0]) else c[0]
        key = ident(keynode) if tag(keynode) == 'identifier' else literal(keynode)
        yield key, c[-1]


def template_parts(text):
    """Locate interpolations without changing their contents or evaluating them."""
    pieces = []
    start = 0
    i = 0
    while i < len(text):
        if text.startswith(('$${', '%%{'), i):
            i += 3
            continue
        if not text.startswith(('${', '%{'), i):
            i += 1
            continue
        if i > start:
            pieces.append(('literal', text[start:i]))
        kind = 'expression' if text[i] == '$' else 'directive'
        begin = i + 2
        i = begin
        depth = 1
        quoted = False
        escaped = False
        while i < len(text) and depth:
            ch = text[i]
            if quoted:
                if escaped:
                    escaped = False
                elif ch == '\\':
                    escaped = True
                elif ch == '"':
                    quoted = False
            elif ch == '"':
                quoted = True
            elif ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
            i += 1
        if depth or quoted:
            raise ContractError('AWS_DESIGN_EXPRESSION_NOT_PARSED', 'FORMAT')
        pieces.append((kind, text[begin : i - 1]))
        start = i
    if start < len(text):
        pieces.append(('literal', text[start:]))
    return pieces


def format_type(nodes, types, pending, issue):
    """Static format signature/conversion checks only; never render a value."""
    if not nodes:
        issue('AWS_DESIGN_FORMAT_ARGUMENTS_INVALID')
    if types[0]['kind'] in {'null', 'list', 'set', 'map', 'object', 'tuple'}:
        issue('AWS_DESIGN_FORMAT_TYPE_MISMATCH')
    spec = literal(nodes[0])
    if type(spec) is not str:
        pending.add(
            'Dynamic format specification/argument conversions require Terraform evaluation'
        )
        return typ('string')
    position = 1
    offset = 0
    used = set()
    while offset < len(spec):
        start = spec.find('%', offset)
        if start < 0:
            break
        if spec.startswith('%%', start):
            offset = start + 2
            continue
        match = re.match(r'%(?:\[([0-9]+)\])?(#v|[vtsqbdoxXeEfgG])', spec[start:])
        if not match:
            if start == len(spec) - 1 or re.match(r'%[A-Za-z]', spec[start:]):
                issue('AWS_DESIGN_FORMAT_SPEC_INVALID')
            pending.add(
                'Format flags/width/precision or escaped specification not statically verified'
            )
            return typ('string')
        index = int(match[1]) if match[1] is not None else position
        verb = match[2]
        if index < 1 or index >= len(types):
            issue('AWS_DESIGN_FORMAT_ARGUMENTS_INVALID')
        position = index + 1
        used.add(index)
        offset = start + len(match[0])
        kind = types[index]['kind']
        if verb in {'v', '#v'}:
            continue
        if kind == 'unknown':
            pending.add('Format argument type/conversion not fully known')
            continue
        if kind == 'null' or kind in {'list', 'tuple', 'set', 'map', 'object'}:
            issue('AWS_DESIGN_FORMAT_TYPE_MISMATCH')
        if verb in {'s', 'q'}:
            continue  # Terraform scalar-to-string conversions.
        value = literal(nodes[index])
        if verb == 't':
            if kind == 'bool':
                continue
            if kind != 'string':
                issue('AWS_DESIGN_FORMAT_TYPE_MISMATCH')
            if value is None:
                pending.add('Format string-to-bool conversion requires actual input')
            elif value not in {'true', 'false'}:
                issue('AWS_DESIGN_FORMAT_TYPE_MISMATCH')
        elif kind != 'number':
            if kind != 'string':
                issue('AWS_DESIGN_FORMAT_TYPE_MISMATCH')
            if value is None:
                pending.add('Format string-to-number conversion requires actual input')
            else:
                from decimal import Decimal, InvalidOperation

                try:
                    valid = Decimal(value).is_finite()
                except InvalidOperation:
                    valid = False
                if not valid:
                    issue('AWS_DESIGN_FORMAT_TYPE_MISMATCH')
    # Explicit indexes may skip earlier arguments, but trailing unused
    # arguments are a definite Terraform error (verified against CLI1.17.2).
    if max(used, default=0) < len(types) - 1:
        issue('AWS_DESIGN_FORMAT_ARGUMENTS_INVALID')
    return typ('string')


class Inspector:
    def __init__(self, terraform, path=''):
        self.tf = terraform
        self.refs = set()
        self.pending = set()
        self.active = set()
        self.local_types = {}
        self.context = [p.replace('~1', '/').replace('~0', '~') for p in path.split('/')[1:]]
        self.variables = {
            name: declaration_type(row.get('type'))
            for name, row in terraform.get('variable', {}).items()
        }

    def issue(self, code):
        raise ContractError(code)

    def value_at(self, value, context):
        old = self.context
        self.context = context
        try:
            return self.value(value, {})
        finally:
            self.context = old

    def iteration(self, owner):
        """Follow the declared iterator, never evaluate its values or invent IDs."""
        key = ('for_each', *owner)
        if key in self.active:
            self.issue('AWS_DESIGN_ITERATOR_CYCLE')
        block = self.tf[owner[0]][owner[1]][owner[2]]
        if 'for_each' not in block:
            self.issue('AWS_DESIGN_EACH_OUTSIDE_FOR_EACH')
        if 'count' in block:
            self.issue('AWS_DESIGN_MULTIPLE_ITERATION_MODES')
        self.active.add(key)
        try:
            collection = self.value_at(block['for_each'], owner + ['for_each'])
        finally:
            self.active.remove(key)
        kind = collection['kind']
        if kind in {'map', 'object'}:
            return typ('string'), self.element(collection)
        if kind == 'set':
            item = self.element(collection)
            if item['kind'] not in {'string', 'unknown'}:
                self.issue('AWS_DESIGN_FOR_EACH_TYPE_INVALID')
            return item, item
        if kind == 'unknown':
            self.pending.add('Iterator collection/key type is not known')
            return typ('string'), ANY
        self.issue('AWS_DESIGN_FOR_EACH_TYPE_INVALID')

    def each(self):
        if not self.context:
            raise ContractError('AWS_DESIGN_EACH_CONTEXT_UNAVAILABLE', 'NOT_VERIFIED')
        owner = self.context[:3]
        if (
            len(owner) != 3
            or owner[0] not in {'resource', 'data'}
            or self.context[3:4] == ['for_each']
        ):
            self.issue('AWS_DESIGN_EACH_OUTSIDE_FOR_EACH')
        key, value = self.iteration(owner)
        return typ('object', attrs={'key': key, 'value': value})

    def path(self, n):
        n = unwrap(n)
        if tag(n) == 'identifier':
            return [ident(n)]
        if tag(n) == 'get_attr_expr_term':
            c = kids(n)
            head = self.path(c[0])
            return head + [ident(kids(c[1])[0])] if head else None
        return None

    def reference(self, path, scope):
        head = path[0]
        if head in scope:
            value = scope[head]
            for part in path[1:]:
                value = self.attribute(value, part)
            return value
        if head == 'var' and len(path) >= 2:
            name = path[1]
            if name not in self.variables:
                self.issue('AWS_DESIGN_VARIABLE_UNDECLARED')
            self.refs.add('var.' + name)
            value = self.variables[name]
            if has_unknown_type(value):
                self.pending.add('Variable type not fully known: var.' + name)
            for part in path[2:]:
                value = self.attribute(value, part)
            return value
        if head == 'local' and len(path) >= 2:
            name = path[1]
            if name not in self.tf.get('locals', {}):
                self.issue('AWS_DESIGN_LOCAL_UNDECLARED')
            self.refs.add('local.' + name)
            if name in self.active:
                self.issue('AWS_DESIGN_LOCAL_CYCLE')
            if name not in self.local_types:
                self.active.add(name)
                try:
                    self.local_types[name] = self.value_at(
                        self.tf['locals'][name], ['locals', name]
                    )
                finally:
                    self.active.remove(name)
            value = self.local_types[name]
            for part in path[2:]:
                value = self.attribute(value, part)
            return value
        if head == 'data' and len(path) >= 3:
            if path[2] not in self.tf.get('data', {}).get(path[1], {}):
                self.issue('AWS_DESIGN_DATA_UNDECLARED')
            self.refs.add('.'.join(path[:3]))
            self.pending.add('Provider data attributes/types are not checked')
            if len(path) == 3 and 'for_each' in self.tf['data'][path[1]][path[2]]:
                self.iteration(['data', path[1], path[2]])
                return typ('map', element=ANY)
            return ANY
        if head in self.tf.get('resource', {}) and len(path) >= 2:
            if path[1] not in self.tf['resource'][head]:
                self.issue('AWS_DESIGN_RESOURCE_UNDECLARED')
            self.refs.add('.'.join(path[:2]))
            self.pending.add('Provider resource attributes/types are not checked')
            if len(path) == 2 and 'for_each' in self.tf['resource'][head][path[1]]:
                self.iteration(['resource', head, path[1]])
                return typ('map', element=ANY)
            return ANY
        if head == 'each':
            value = self.each()
            for part in path[1:]:
                value = self.attribute(value, part)
            return value
        if head in {'path', 'terraform', 'count', 'self'}:
            self.pending.add('Context-dependent reference not checked: ' + '.'.join(path))
            return ANY
        if head in {'var', 'local', 'data'}:
            self.issue('AWS_DESIGN_REFERENCE_INCOMPLETE')
        self.issue('AWS_DESIGN_REFERENCE_UNDECLARED')

    def attribute(self, t, key):
        if t['kind'] == 'object':
            if key not in t['attrs']:
                self.issue('AWS_DESIGN_ATTRIBUTE_UNDECLARED')
            return t['attrs'][key]
        if t['kind'] == 'map':
            return t.get('element', ANY)
        if t['kind'] == 'unknown':
            return ANY
        self.issue('AWS_DESIGN_EXPRESSION_TYPE_MISMATCH')

    def element(self, t):
        if t['kind'] in {'map', 'list', 'set'}:
            return t.get('element', ANY)
        if t['kind'] in {'tuple', 'object'}:
            items = t.get('items', list(t.get('attrs', {}).values()))
            return items[0] if items and all(x == items[0] for x in items) else ANY
        if t['kind'] == 'unknown':
            return ANY
        self.issue('AWS_DESIGN_EXPRESSION_TYPE_MISMATCH')

    def value(self, value, scope):
        if value is None:
            return typ('null')
        if type(value) is bool:
            return typ('bool')
        if type(value) in (int, float):
            return typ('number')
        if isinstance(value, list):
            return typ('tuple', items=[self.value(x, scope) for x in value])
        if isinstance(value, dict):
            return typ('object', attrs={k: self.value(x, scope) for k, x in value.items()})
        if '${' not in value and '%{' not in value:
            return typ('string')
        pieces = template_parts(value)
        types = []
        for kind, text in pieces:
            if kind != 'expression':
                continue
            try:
                types.append(self.infer(parse(text), scope))
            except ImportError:
                self.pending.add('HCL2 syntax/reference/type parser unavailable')
                simple = re.fullmatch(r'var\.([A-Za-z_][A-Za-z0-9_-]*)', text.strip())
                types.append(self.reference(['var', simple[1]], scope) if simple else ANY)
            except ContractError:
                raise
            except Exception:
                raise ContractError('AWS_DESIGN_EXPRESSION_NOT_PARSED', 'NOT_VERIFIED') from None
        if len(pieces) == 1 and pieces[0][0] == 'expression':
            return types[0]
        if any(k == 'directive' for k, _ in pieces):
            self.pending.add('Template directive semantics not checked')
        if any(t['kind'] in {'object', 'tuple', 'map', 'list', 'set'} for t in types):
            self.issue('AWS_DESIGN_TEMPLATE_TYPE_MISMATCH')
        return typ('string')

    def string(self, n, scope, json_mapping=False):
        interpolations = []
        literal_text = False
        directives = False
        for part in kids(n):
            for sub in kids(part):
                if tag(sub) == 'interpolation':
                    interpolations.append(sub)
                else:
                    directives = True
            if not kids(part) and any(str(c) for c in part.children):
                literal_text = True
        types = [self.infer(kids(x)[0], scope) for x in interpolations]
        if directives:
            self.pending.add('Template directive semantics not checked')
        if json_mapping and len(types) == 1 and not literal_text and not directives:
            return types[0]
        if any(t['kind'] in {'object', 'tuple', 'map', 'list', 'set'} for t in types):
            self.issue('AWS_DESIGN_TEMPLATE_TYPE_MISMATCH')
        return typ('string')

    def infer(self, node, scope):
        n = unwrap(node)
        t = tag(n)
        c = kids(n)
        if t == 'identifier':
            name = ident(n)
            if name in {'true', 'false'}:
                return typ('bool')
            if name == 'null':
                return typ('null')
            return self.reference([name], scope)
        if t == 'get_attr_expr_term':
            path = self.path(n)
            return (
                self.reference(path, scope)
                if path
                else self.attribute(self.infer(c[0], scope), ident(kids(c[1])[0]))
            )
        if t in {'int_lit', 'float_lit'}:
            return typ('number')
        if t == 'string':
            return self.string(n, scope)
        if t == 'tuple':
            return typ('tuple', items=[self.infer(x, scope) for x in c])
        if t == 'object':
            attrs = {}
            dynamic = False
            for item in c:
                if tag(item) != 'object_elem':
                    continue
                parts = kids(item)
                keynode = kids(parts[0])[0] if kids(parts[0]) else parts[0]
                key = ident(keynode) if tag(keynode) == 'identifier' else literal(keynode)
                val = parts[-1]
                if key is None:
                    dynamic = True
                    self.infer(keynode, scope)
                    self.pending.add('Dynamic object key uniqueness/value is not checked')
                attrs[key] = self.infer(val, scope)
            if dynamic:
                values = list(attrs.values())
                return typ(
                    'map',
                    element=values[0] if values and all(x == values[0] for x in values) else ANY,
                )
            return typ('object', attrs=attrs)
        if t in {'for_tuple_expr', 'for_object_expr'}:
            intro = next(x for x in c if tag(x) == 'for_intro')
            ic = kids(intro)
            names = [ident(x) for x in ic if tag(x) == 'identifier']
            collection = self.infer(ic[-1], scope)
            item = self.element(collection)
            nested = {**scope, names[-1]: item}
            if len(names) == 2:
                nested[names[0]] = typ(
                    'string' if collection['kind'] in {'map', 'object'} else 'number'
                )
            outputs = [x for x in c if tag(x) not in {'for_intro', 'for_cond'}]
            values = [self.infer(x, nested) for x in outputs]
            for cond in [x for x in c if tag(x) == 'for_cond']:
                check = self.infer(kids(cond)[0], nested)
                if check['kind'] in {'object', 'tuple', 'list', 'map', 'set'}:
                    self.issue('AWS_DESIGN_EXPRESSION_TYPE_MISMATCH')
            if collection['kind'] == 'unknown':
                self.pending.add('Collection input type not known')
            if t == 'for_object_expr':
                if values[0]['kind'] in {'map', 'object', 'list', 'tuple', 'set'}:
                    self.issue('AWS_DESIGN_EXPRESSION_TYPE_MISMATCH')
                self.pending.add('Object comprehension key uniqueness/grouping is not checked')
            return (
                typ('list', element=values[-1])
                if t == 'for_tuple_expr'
                else typ('map', element=values[-1])
            )
        if t == 'index_expr_term':
            index = kids(c[1])[0]
            key = literal(index)
            head = self.path(c[0])
            if head in (['var'], ['local']) and isinstance(key, str):
                return self.reference(head + [key], scope)
            base = self.infer(c[0], scope)
            self.infer(index, scope)
            if (
                base['kind'] in {'tuple', 'list', 'set'}
                and isinstance(key, str)
                and not re.fullmatch(r'-?[0-9]+', key)
            ):
                self.issue('AWS_DESIGN_EXPRESSION_TYPE_MISMATCH')
            if base['kind'] == 'object' and isinstance(key, str):
                return self.attribute(base, key)
            if base['kind'] == 'tuple' and type(key) is int:
                if key < 0 or key >= len(base['items']):
                    self.issue('AWS_DESIGN_INDEX_OUT_OF_RANGE')
                return base['items'][key]
            return self.element(base)
        if t in {'full_splat_expr_term', 'attr_splat_expr_term'}:
            base = self.infer(c[0], scope)
            if base['kind'] == 'null':
                return typ('list', element=ANY)
            item = self.element(base) if base['kind'] in {'list', 'set', 'tuple'} else base
            for access in kids(c[1]):
                if tag(access) == 'get_attr':
                    item = self.attribute(item, ident(kids(access)[0]))
                else:
                    self.pending.add('Splat index/cardinality semantics not checked')
            self.pending.add('Exact splat cardinality is not checked')
            return typ('list', element=item)
        if t == 'function_call':
            name = ident(c[0])
            args = [self.infer(x, scope) for x in (kids(c[1]) if len(c) > 1 else [])]
            if name == 'format':
                return format_type(kids(c[1]) if len(c) > 1 else [], args, self.pending, self.issue)
            if (
                name
                in {
                    'jsonencode',
                    'upper',
                    'lower',
                    'tostring',
                    'keys',
                    'values',
                    'tomap',
                    'tolist',
                    'toset',
                    'length',
                }
                and len(args) != 1
            ):
                self.issue('AWS_DESIGN_EXPRESSION_ARGUMENTS_INVALID')
            if name in {'jsonencode', 'upper', 'lower', 'tostring'}:
                if (
                    name in {'upper', 'lower', 'tostring'}
                    and args
                    and args[0]['kind'] in {'map', 'object', 'list', 'tuple', 'set'}
                ):
                    self.issue('AWS_DESIGN_EXPRESSION_TYPE_MISMATCH')
                return typ('string')
            if name in {'keys', 'values', 'tomap'} and args:
                if args[0]['kind'] not in {'map', 'object', 'unknown'}:
                    self.issue('AWS_DESIGN_EXPRESSION_TYPE_MISMATCH')
                item = typ('string') if name == 'keys' else self.element(args[0])
                return typ('map' if name == 'tomap' else 'list', element=item)
            if name in {'tolist', 'toset', 'concat'} and args:
                for a in args:
                    allowed = (
                        {'list', 'tuple', 'unknown'}
                        if name == 'concat'
                        else {'list', 'tuple', 'set', 'unknown'}
                    )
                    if a['kind'] not in allowed:
                        self.issue('AWS_DESIGN_EXPRESSION_TYPE_MISMATCH')
                if name == 'concat':
                    self.pending.add('Concat element conversions/cardinality are not checked')
                    elements = [self.element(a) for a in args]
                    return typ(
                        'list',
                        element=elements[0] if all(x == elements[0] for x in elements) else ANY,
                    )
                return typ('set' if name == 'toset' else 'list', element=self.element(args[0]))
            if name == 'length':
                if args[0]['kind'] not in {
                    'string',
                    'list',
                    'tuple',
                    'set',
                    'map',
                    'object',
                    'unknown',
                }:
                    self.issue('AWS_DESIGN_EXPRESSION_TYPE_MISMATCH')
                return typ('number')
            self.pending.add('Function semantics not checked: ' + name)
            return ANY
        # Do not infer types from the parser's conditional/operator precedence.
        # Walk their references, but leave conversion/operator details to review.
        if t in {'binary_op', 'binary_term', 'conditional', 'unary_op'}:
            for x in c:
                if tag(x) not in {'binary_operator', 'unary_operator'}:
                    self.infer(x, scope)
            self.pending.add('Operator/conditional result type not checked')
            return ANY
        if t not in {'get_attr', 'object_elem_key'}:
            for x in c:
                self.infer(x, scope)
        self.pending.add('HCL construct not type-checked: ' + t)
        return ANY


def literal_context(path):
    parts = [p.replace('~1', '/').replace('~0', '~') for p in path.split('/')[1:]]
    if not parts:
        return False
    if parts[0] in {'terraform', 'variable'}:
        return True
    if parts[0] == 'output' and len(parts) == 3 and parts[-1] in {'description', 'sensitive'}:
        return True
    if parts[0] == 'provider' and parts[-1] in {'alias', 'version'}:
        return True
    if parts[0] in {'resource', 'data'} and len(parts) > 3:
        if parts[3] in {'provider', 'depends_on'}:
            return True
        if parts[3] == 'lifecycle' and 'ignore_changes' in parts[4:]:
            return True
    return False


def check(terraform, value, *, require_variable=False, path=''):
    if literal_context(path):
        if require_variable:
            raise ContractError('AWS_DESIGN_EXPRESSION_IN_LITERAL_CONTEXT')
        return {
            'result_type': typ('string' if isinstance(value, str) else 'literal'),
            'references': [],
            'unverified': [
                'Block-specific literal/meta-argument semantics require Terraform validation'
            ],
            'terraform_validation': 'NOT_RUN',
            'requires_review': True,
        }
    inspector = Inspector(terraform, path)
    result = inspector.value(value, {})
    if require_variable:
        if not isinstance(value, str) or ('${' not in value and '%{' not in value):
            raise ContractError('AWS_DESIGN_UNKNOWN_MUST_REFERENCE_INPUT', 'FORMAT')
        dependency = any(not x.startswith('local.') for x in inspector.refs)
        if (
            not dependency
            and 'HCL2 syntax/reference/type parser unavailable' not in inspector.pending
        ):
            raise ContractError('AWS_DESIGN_UNKNOWN_MUST_REFERENCE_INPUT', 'INFORMATION')
    if has_unknown_type(result):
        inspector.pending.add('Expression result type is not fully known')
    return {
        'result_type': result,
        'references': sorted(inspector.refs),
        'unverified': sorted(inspector.pending),
        'terraform_validation': 'NOT_RUN',
        'requires_review': True,
    }
