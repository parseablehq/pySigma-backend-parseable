"""Convert Sigma rules to SQL accepted by Parseable's DataFusion query engine."""

from __future__ import annotations

import re
from typing import Any, ClassVar

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionItem,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.exceptions import SigmaConfigurationError, SigmaFeatureNotSupportedByBackendError
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
    SpecialChars,
)


class ParseableBackend(TextQueryBackend):
    """Parseable SQL backend.

    Backend owns SQL syntax only. Processing pipelines remain responsible for mapping
    abstract Sigma fields to columns present in a particular Parseable dataset.
    """

    name: ClassVar[str] = "parseable"
    formats: ClassVar[dict[str, str]] = {
        "default": "Complete Parseable SQL query",
        "predicate": "Parseable SQL WHERE predicate",
    }
    requires_pipeline: ClassVar[bool] = False
    correlation_methods: ClassVar[None] = None

    precedence: ClassVar[tuple[type[ConditionItem], type[ConditionItem], type[ConditionItem]]] = (
        ConditionNOT,
        ConditionAND,
        ConditionOR,
    )
    parenthesize: ClassVar[bool] = True
    group_expression: ClassVar[str] = "({expr})"
    token_separator: ClassVar[str] = " "
    or_token: ClassVar[str] = "OR"
    and_token: ClassVar[str] = "AND"
    not_token: ClassVar[str] = "NOT"

    field_quote: ClassVar[str] = '"'
    field_quote_pattern: ClassVar[None] = None  # Always quote identifiers.
    field_escape: ClassVar[str] = '"'  # SQL identifier quote escapes by doubling.
    field_escape_quote: ClassVar[bool] = True
    field_escape_pattern: ClassVar[None] = None

    str_quote: ClassVar[str] = "'"
    escape_char: ClassVar[str] = "\\"
    wildcard_multi: ClassVar[str] = "%"
    wildcard_single: ClassVar[str] = "_"
    add_escaped: ClassVar[str] = "%_"
    filter_chars: ClassVar[str] = ""
    bool_values: ClassVar[dict[bool, str]] = {True: "TRUE", False: "FALSE"}

    eq_token: ClassVar[str] = " = "
    eq_expression: ClassVar[str] = "LOWER({field}) = {value}"
    startswith_expression: ClassVar[str] = "LOWER({field}) LIKE {value} ESCAPE '\\'"
    endswith_expression: ClassVar[str] = "LOWER({field}) LIKE {value} ESCAPE '\\'"
    contains_expression: ClassVar[str] = "LOWER({field}) LIKE {value} ESCAPE '\\'"
    wildcard_match_expression: ClassVar[str] = "LOWER({field}) LIKE {value} ESCAPE '\\'"

    case_sensitive_match_expression: ClassVar[str] = "{field} = {value}"
    case_sensitive_startswith_expression: ClassVar[str] = "{field} LIKE {value} ESCAPE '\\'"
    case_sensitive_endswith_expression: ClassVar[str] = "{field} LIKE {value} ESCAPE '\\'"
    case_sensitive_contains_expression: ClassVar[str] = "{field} LIKE {value} ESCAPE '\\'"

    re_expression: ClassVar[str] = "regexp_like({field}, '{regex}')"
    re_escape_char: ClassVar[str] = "\\"
    re_escape: ClassVar[tuple[str, ...]] = ("'",)
    re_escape_escape_char: ClassVar[bool] = False
    re_flag_prefix: ClassVar[bool] = True

    field_null_expression: ClassVar[str] = "{field} IS NULL"
    field_exists_expression: ClassVar[str] = "{field} IS NOT NULL"
    field_not_exists_expression: ClassVar[str] = "{field} IS NULL"

    field_equals_field_expression: ClassVar[str] = "LOWER({field1}) = LOWER({field2})"
    field_equals_field_startswith_expression: ClassVar[str] = (
        "starts_with(LOWER({field1}), LOWER({field2}))"
    )
    field_equals_field_endswith_expression: ClassVar[str] = (
        "ends_with(LOWER({field1}), LOWER({field2}))"
    )
    field_equals_field_contains_expression: ClassVar[str] = (
        "strpos(LOWER({field1}), LOWER({field2})) > 0"
    )
    field_equals_field_escaping_quoting: ClassVar[tuple[bool, bool]] = (True, True)

    compare_op_expression: ClassVar[str] = "{field} {operator} {value}"
    compare_operators: ClassVar[dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    convert_or_as_in: ClassVar[bool] = True
    convert_and_as_in: ClassVar[bool] = False
    in_expressions_allow_wildcards: ClassVar[bool] = False
    field_in_list_expression: ClassVar[str] = "{field} {op} ({list})"
    or_in_operator: ClassVar[str] = "IN"
    list_separator: ClassVar[str] = ", "

    cidr_expression: ClassVar[None] = None
    deferred_start: ClassVar[None] = None
    deferred_separator: ClassVar[None] = None
    deferred_only_query: ClassVar[None] = None

    _SAFE_INTEGER = re.compile(r"^(0|[1-9][0-9]*)$")

    def __init__(
        self,
        processing_pipeline: Any = None,
        collect_errors: bool = False,
        **backend_options: Any,
    ) -> None:
        super().__init__(processing_pipeline, collect_errors, **backend_options)
        dataset = backend_options.get("dataset")
        self.dataset = str(dataset).strip() if dataset is not None else ""
        self.limit = self._parse_limit(backend_options.get("limit"))
        search_fields = backend_options.get("default_search_fields", "body,message,event.original")
        if isinstance(search_fields, str):
            search_fields = [field.strip() for field in search_fields.split(",")]
        self.default_search_fields = [str(field) for field in search_fields if str(field).strip()]

    @classmethod
    def _parse_limit(cls, value: Any) -> int | None:
        if value is None or value == "":
            return None
        text = str(value)
        if not cls._SAFE_INTEGER.fullmatch(text) or int(text) < 1:
            raise SigmaConfigurationError("Parseable limit must be a positive integer.")
        return int(text)

    @staticmethod
    def _sql_string(value: str) -> str:
        return "'" + value.replace("'", "''") + "'"

    def _render_string(self, value: SigmaString, *, like: bool, cased: bool) -> str:
        if like:
            rendered = value.convert("\\", "%", "_", "\\%_", "")
        else:
            rendered = value.convert("", "%", "_", "", "")
        if not cased:
            rendered = rendered.casefold()
        return self._sql_string(rendered)

    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str | DeferredQueryExpression:
        value = cond.value
        if not isinstance(value, SigmaString):
            raise TypeError(f"Expected SigmaString, got {type(value)}")

        field = self.escape_and_quote_field(cond.field)
        if value.startswith(SpecialChars.WILDCARD_MULTI) and value.endswith(
            SpecialChars.WILDCARD_MULTI
        ):
            expression, actual, like = self.contains_expression, value, True
        elif value.endswith(SpecialChars.WILDCARD_MULTI):
            expression, actual, like = self.startswith_expression, value, True
        elif value.startswith(SpecialChars.WILDCARD_MULTI):
            expression, actual, like = self.endswith_expression, value, True
        elif value.contains_special():
            expression, actual, like = self.wildcard_match_expression, value, True
        else:
            expression, actual, like = self.eq_expression, value, False

        return expression.format(
            field=field,
            value=self._render_string(actual, like=like, cased=False),
            backend=self,
        )

    def convert_condition_field_eq_val_str_case_sensitive(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str | DeferredQueryExpression:
        value = cond.value
        if not isinstance(value, SigmaString):
            raise TypeError(f"Expected SigmaString, got {type(value)}")
        field = self.escape_and_quote_field(cond.field)

        if value.startswith(SpecialChars.WILDCARD_MULTI) and value.endswith(
            SpecialChars.WILDCARD_MULTI
        ):
            expression, like = self.case_sensitive_contains_expression, True
        elif value.endswith(SpecialChars.WILDCARD_MULTI):
            expression, like = self.case_sensitive_startswith_expression, True
        elif value.startswith(SpecialChars.WILDCARD_MULTI):
            expression, like = self.case_sensitive_endswith_expression, True
        elif value.contains_special():
            expression, like = "{field} LIKE {value} ESCAPE '\\'", True
        else:
            expression, like = self.case_sensitive_match_expression, False

        return expression.format(
            field=field,
            value=self._render_string(value, like=like, cased=True),
            backend=self,
        )

    def convert_condition_as_in_expression(
        self, cond: ConditionOR | ConditionAND, state: ConversionState
    ) -> str | DeferredQueryExpression:
        first = cond.args[0]
        field = self.escape_and_quote_field(first.field)
        cased = isinstance(first.value, SigmaCasedString)
        if isinstance(first.value, SigmaString) and not cased:
            field = f"LOWER({field})"
        values = self.list_separator.join(
            self._render_in_value(arg.value, cased=cased) for arg in cond.args
        )
        return self.field_in_list_expression.format(field=field, op=self.or_in_operator, list=values)

    def _render_in_value(self, value: Any, *, cased: bool) -> str:
        if isinstance(value, SigmaString):
            return self._render_string(value, like=False, cased=cased)
        if isinstance(value, SigmaNumber):
            return str(value.number)
        if isinstance(value, SigmaBool):
            return self.bool_values[value.boolean]
        raise TypeError(f"Unsupported Parseable IN-list value: {type(value)}")

    def convert_value_re(
        self, value: SigmaRegularExpression, state: ConversionState
    ) -> str | DeferredQueryExpression:
        # DataFusion uses SQL string literals around regexes. Preserve regex backslashes,
        # but double apostrophes so regex content cannot terminate the literal.
        return value.escape((), "\\", False, True).replace("'", "''")

    def convert_condition_val_str(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> str | DeferredQueryExpression:
        if not isinstance(cond.value, SigmaString):
            raise TypeError(f"Expected SigmaString, got {type(cond.value)}")
        if not self.default_search_fields:
            raise SigmaConfigurationError(
                "Value-only Sigma keywords require default_search_fields."
            )
        value = cond.value
        if not value.contains_special():
            wrapped = SigmaString()
            wrapped.s = [SpecialChars.WILDCARD_MULTI, *value.s, SpecialChars.WILDCARD_MULTI]
        else:
            wrapped = value
        rendered = self._render_string(wrapped, like=True, cased=False)
        return "(" + " OR ".join(
            f"LOWER({self.escape_and_quote_field(field)}) LIKE {rendered} ESCAPE '\\'"
            for field in self.default_search_fields
        ) + ")"

    @staticmethod
    def _unsupported(feature: str, source: Any = None) -> None:
        raise SigmaFeatureNotSupportedByBackendError(
            f"Parseable backend does not support {feature}.", source=source
        )

    def convert_condition_field_eq_val_cidr(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str | DeferredQueryExpression:
        cidr = cond.value
        if not isinstance(cidr, SigmaCIDRExpression):
            raise TypeError(f"Expected SigmaCIDRExpression, got {type(cidr)}")
        field = self.escape_and_quote_field(cond.field)
        return f"ip_in_cidr({field}, {self._sql_string(str(cidr.network))})"

    def convert_condition_field_eq_val_timestamp_part(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str | DeferredQueryExpression:
        self._unsupported("timestamp-part modifiers", cond.source)

    def convert_condition_val_num(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> str | DeferredQueryExpression:
        if not self.default_search_fields:
            raise SigmaConfigurationError(
                "Value-only Sigma numeric keywords require default_search_fields."
            )
        value = str(cond.value)
        pattern = f"(^|[^0-9.+-]){re.escape(value)}([^0-9.]|$)"
        rendered = self._sql_string(pattern)
        return "(" + " OR ".join(
            f"regexp_like(CAST({self.escape_and_quote_field(field)} AS VARCHAR), {rendered})"
            for field in self.default_search_fields
        ) + ")"

    def convert_condition_val_re(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> str | DeferredQueryExpression:
        self._unsupported("unbound regular-expression searches", cond.source)

    def convert_correlation_rule(
        self,
        rule: Any,
        output_format: str | None = None,
        method: str | None = None,
        callback: Any = None,
    ) -> list[Any]:
        self._unsupported("Sigma correlation rules", getattr(rule, "source", None))

    def finalize_query_default(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> str:
        if not self.dataset:
            raise SigmaConfigurationError(
                "Parseable dataset required. Pass -O dataset=<name>."
            )
        fields = rule.fields or ["*"]
        selected = ", ".join(
            field if field == "*" else self.escape_and_quote_field(field) for field in fields
        )
        sql = f"SELECT {selected} FROM {self.escape_and_quote_field(self.dataset)} WHERE {query}"
        if self.limit is not None:
            sql += f" LIMIT {self.limit}"
        return sql

    def finalize_query_predicate(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> str:
        return query

    def finalize_output_predicate(self, queries: list[str]) -> list[str]:
        return queries
