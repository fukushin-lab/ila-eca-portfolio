"""G-only regression: lexical scope, capacities, shared isolation, durable replay."""

from io import BytesIO
from pathlib import Path
from unittest.mock import patch
import copy, json, unittest
from ILA_ECA_REAL_DISCOVERY_LAB.design import expressions as e
from ILA_ECA_REAL_DISCOVERY_LAB.llm import generation as route_llm
from ILA_ECA_REAL_DISCOVERY_LAB.llm import runtime as old
from ILA_ECA_REAL_DISCOVERY_LAB.llm import cloud as cloud


class EachTests(unittest.TestCase):
    def tf(self):
        return {
            'variable': {'items': {'type': 'map(object({id=string}))'}},
            'resource': {
                'synthetic': {
                    'first': {'for_each': '${var.items}', 'id': '${each.value.id}'},
                    'second': {'for_each': '${synthetic.first}', 'id': '${each.value.id}'},
                }
            },
        }

    def check(self, tf=None, value='${each.value.id}', path='/resource/synthetic/second/id'):
        return e.check(tf or self.tf(), value, require_variable=True, path=path)

    def test_resource_chaining_tracks_actual_dependency(self):
        result = self.check()
        self.assertIn('synthetic.first', result['references'])
        self.assertIn('var.items', result['references'])
        self.assertTrue(result['unverified'])  # Provider attribute schemas stay unverified.

    def test_typed_map_each_value_attribute(self):
        result = self.check(path='/resource/synthetic/first/id')
        self.assertEqual(result['result_type']['kind'], 'string')

    def test_unknown_attribute_is_rejected(self):
        with self.assertRaisesRegex(e.ContractError, 'ATTRIBUTE_UNDECLARED'):
            self.check(value='${each.value.missing}', path='/resource/synthetic/first/id')

    def test_undefined_iterator_input_is_rejected(self):
        tf = self.tf()
        tf['resource']['synthetic']['first']['for_each'] = '${var.missing}'
        with self.assertRaisesRegex(e.ContractError, 'VARIABLE_UNDECLARED'):
            self.check(tf)

    def test_noncollection_iterator_is_rejected(self):
        tf = self.tf()
        tf['resource']['synthetic']['first']['for_each'] = 123
        with self.assertRaisesRegex(e.ContractError, 'FOR_EACH_TYPE_INVALID'):
            self.check(tf)

    def test_list_is_not_implicitly_accepted_as_for_each(self):
        tf = self.tf()
        tf['resource']['synthetic']['first']['for_each'] = ['one']
        with self.assertRaisesRegex(e.ContractError, 'FOR_EACH_TYPE_INVALID'):
            self.check(tf)

    def test_scope_outside_iterator_is_rejected(self):
        tf = self.tf()
        tf['resource']['synthetic']['second'].pop('for_each')
        with self.assertRaisesRegex(e.ContractError, 'EACH_OUTSIDE_FOR_EACH'):
            self.check(tf)

    def test_for_each_cannot_refer_to_its_own_each(self):
        tf = self.tf()
        tf['resource']['synthetic']['first']['for_each'] = '${each.value}'
        with self.assertRaisesRegex(e.ContractError, 'EACH_OUTSIDE_FOR_EACH'):
            self.check(tf)

    def test_local_cannot_borrow_callers_each_scope(self):
        tf = self.tf()
        tf['locals'] = {'bad': '${each.value.id}'}
        with self.assertRaisesRegex(e.ContractError, 'EACH_OUTSIDE_FOR_EACH'):
            self.check(tf, value='${local.bad}')

    def test_iterator_cycle_is_rejected(self):
        tf = self.tf()
        tf['resource']['synthetic']['first']['for_each'] = '${synthetic.second}'
        with self.assertRaisesRegex(e.ContractError, 'ITERATOR_CYCLE'):
            self.check(tf)

    def test_missing_context_is_not_claimed_terraform_error(self):
        with self.assertRaises(e.ContractError) as c:
            self.check(path='')
        self.assertEqual(c.exception.category, 'NOT_VERIFIED')

    def test_set_each_key_and_value_have_string_type(self):
        tf = self.tf()
        tf['variable']['items'] = {'type': 'set(string)'}
        for expr in ['${each.key}', '${each.value}']:
            result = self.check(tf, value=expr, path='/resource/synthetic/first/id')
            self.assertEqual(result['result_type']['kind'], 'string')

    def test_count_and_for_each_cannot_coexist(self):
        tf = self.tf()
        tf['resource']['synthetic']['first']['count'] = 1
        with self.assertRaisesRegex(e.ContractError, 'MULTIPLE_ITERATION_MODES'):
            self.check(tf)
