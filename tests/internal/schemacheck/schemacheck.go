// Package schemacheck validates a JSON document against the subset of JSON
// Schema that pqc-fixtures' published manifest schema actually uses.
//
// It exists so design-dossier §8 criterion 4 ("every Manifest validates
// against its published JSON Schema") is enforced by the test suite without
// adding a dependency to a project whose audience is professionally paranoid
// about supply chain (§9, ADR-010). It is test-support code and is never
// compiled into the shipped binary.
//
// The safety property that makes a hand-written subset acceptable: any schema
// keyword it does not implement is a hard error, not a silent pass. If the
// manifest schema grows beyond this subset, the test fails and the choice
// (extend this, or take the dependency) is made deliberately.
package schemacheck

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// supported lists every JSON Schema keyword this validator understands.
// Annotations are accepted and ignored; the rest are enforced.
var supported = map[string]bool{
	// Annotations.
	"$schema": true, "$id": true, "title": true, "description": true,
	// Enforced.
	"type": true, "properties": true, "required": true,
	"additionalProperties": true, "items": true, "enum": true,
	"const": true, "minimum": true, "pattern": true,
}

// Validate checks document against schema, returning every violation found.
func Validate(schema, document []byte) error {
	var s any
	if err := json.Unmarshal(schema, &s); err != nil {
		return fmt.Errorf("schema is not valid JSON: %w", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(document)))
	dec.UseNumber()
	var d any
	if err := dec.Decode(&d); err != nil {
		return fmt.Errorf("document is not valid JSON: %w", err)
	}

	v := &validator{}
	v.check(s, d, "$")
	if len(v.problems) == 0 {
		return nil
	}
	return fmt.Errorf("document does not match schema:\n  %s", strings.Join(v.problems, "\n  "))
}

type validator struct {
	problems []string
}

func (v *validator) fail(path, format string, args ...any) {
	v.problems = append(v.problems, path+": "+fmt.Sprintf(format, args...))
}

func (v *validator) check(rawSchema, value any, path string) {
	schema, ok := rawSchema.(map[string]any)
	if !ok {
		v.fail(path, "schema fragment is not an object")
		return
	}
	for keyword := range schema {
		if !supported[keyword] {
			v.fail(path, "schema uses unsupported keyword %q; extend schemacheck or take a JSON Schema dependency", keyword)
			return
		}
	}

	if want, ok := schema["type"].(string); ok && !hasType(value, want) {
		v.fail(path, "expected type %s, got %s", want, describe(value))
		return
	}
	if allowed, ok := schema["enum"].([]any); ok && !containsJSON(allowed, value) {
		v.fail(path, "value %v is not one of %v", value, allowed)
	}
	if expected, ok := schema["const"]; ok && !equalJSON(expected, value) {
		v.fail(path, "value %v must equal %v", value, expected)
	}
	if minimum, ok := schema["minimum"]; ok {
		if n, err := toFloat(value); err == nil {
			if m, err := toFloat(minimum); err == nil && n < m {
				v.fail(path, "value %v is below the minimum %v", value, minimum)
			}
		}
	}
	if pattern, ok := schema["pattern"].(string); ok {
		if s, isString := value.(string); isString {
			re, err := regexp.Compile(pattern)
			if err != nil {
				v.fail(path, "schema pattern %q does not compile: %v", pattern, err)
			} else if !re.MatchString(s) {
				v.fail(path, "value %q does not match %s", s, pattern)
			}
		}
	}

	switch typed := value.(type) {
	case map[string]any:
		v.checkObject(schema, typed, path)
	case []any:
		if items, ok := schema["items"]; ok {
			for i, item := range typed {
				v.check(items, item, fmt.Sprintf("%s[%d]", path, i))
			}
		}
	}
}

func (v *validator) checkObject(schema map[string]any, value map[string]any, path string) {
	properties, _ := schema["properties"].(map[string]any)

	if required, ok := schema["required"].([]any); ok {
		for _, name := range required {
			key, _ := name.(string)
			if _, present := value[key]; !present {
				v.fail(path, "missing required property %q", key)
			}
		}
	}

	if allowExtra, ok := schema["additionalProperties"].(bool); ok && !allowExtra {
		var extra []string
		for key := range value {
			if _, declared := properties[key]; !declared {
				extra = append(extra, key)
			}
		}
		sort.Strings(extra)
		for _, key := range extra {
			v.fail(path, "property %q is not declared in the schema", key)
		}
	}

	for key, sub := range properties {
		if child, present := value[key]; present {
			v.check(sub, child, path+"."+key)
		}
	}
}

func hasType(value any, want string) bool {
	switch want {
	case "object":
		_, ok := value.(map[string]any)
		return ok
	case "array":
		_, ok := value.([]any)
		return ok
	case "string":
		_, ok := value.(string)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "null":
		return value == nil
	case "integer":
		n, ok := value.(json.Number)
		if !ok {
			return false
		}
		_, err := n.Int64()
		return err == nil
	case "number":
		_, ok := value.(json.Number)
		return ok
	default:
		return false
	}
}

func describe(value any) string {
	switch typed := value.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	case json.Number:
		if _, err := typed.Int64(); err == nil {
			return "integer"
		}
		return "number"
	default:
		return fmt.Sprintf("%T", value)
	}
}

func toFloat(value any) (float64, error) {
	switch typed := value.(type) {
	case json.Number:
		return typed.Float64()
	case float64:
		return typed, nil
	default:
		return 0, fmt.Errorf("not numeric")
	}
}

func equalJSON(a, b any) bool {
	an, aok := a.(json.Number)
	bn, bok := b.(json.Number)
	if aok && bok {
		return an.String() == bn.String()
	}
	if af, err := toFloat(a); err == nil {
		if bf, err := toFloat(b); err == nil {
			return af == bf
		}
		return false
	}
	return a == b
}

func containsJSON(candidates []any, value any) bool {
	for _, candidate := range candidates {
		if equalJSON(candidate, value) {
			return true
		}
	}
	return false
}
