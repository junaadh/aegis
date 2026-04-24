use serde_json::{Map, Value};

pub fn generate_schema() -> Value {
    let settings = schemars::r#gen::SchemaSettings::default();
    let mut r#gen = schemars::r#gen::SchemaGenerator::new(settings);
    let schema = r#gen.root_schema_for::<crate::root::Config>();
    let mut value = serde_json::to_value(&schema)
        .expect("schema serialization must not fail");
    post_process(&mut value);
    value
}

fn post_process(root: &mut Value) {
    if let Some(defs) = obj_mut(root, "definitions") {
        for (_, def) in defs.iter_mut() {
            transform_definition(def);
        }
    }

    if let Some(props) = obj_mut(root, "properties") {
        for (_, prop) in props.iter_mut() {
            transform_and_wrap(prop);
        }
    }
}

fn transform_definition(schema: &mut Value) {
    if let Some(props) = obj_mut(schema, "properties") {
        for (_, prop) in props.iter_mut() {
            transform_and_wrap(prop);
        }
    }

    if let Some(all_of) = schema.get_mut("allOf").and_then(|a| a.as_array_mut())
    {
        for item in all_of.iter_mut() {
            transform_definition(item);
        }
    }
}

fn transform_and_wrap(prop: &mut Value) {
    recurse_transform(prop);
    wrap_with_refs(prop);
}

fn recurse_transform(schema: &mut Value) {
    if schema.get("$ref").is_some() {
        return;
    }

    if let Some(props) = obj_mut(schema, "properties") {
        for (_, p) in props.iter_mut() {
            transform_and_wrap(p);
        }
    }

    if let Some(items) = schema.get_mut("items") {
        recurse_into_items(items);
    }

    if let Some(all_of) = schema.get_mut("allOf").and_then(|a| a.as_array_mut())
    {
        for item in all_of.iter_mut() {
            recurse_transform(item);
        }
    }

    if let Some(any_of) = schema.get_mut("anyOf").and_then(|a| a.as_array_mut())
    {
        for item in any_of.iter_mut() {
            if !is_null_type(item) {
                recurse_transform(item);
            }
        }
    }
}

fn recurse_into_items(items: &mut Value) {
    if items.get("$ref").is_some() {
        return;
    }

    if let Some(props) = obj_mut(items, "properties") {
        for (_, p) in props.iter_mut() {
            transform_and_wrap(p);
        }
    }
}

fn wrap_with_refs(prop: &mut Value) {
    let meta = extract_meta(prop);
    let mut native = extract_native(prop);

    fix_integer_formats(&mut native);

    if is_string_type(&native) {
        add_negative_lookahead(&mut native);
    }

    strip_meta(&mut native);

    let mut wrapper = meta;
    wrapper.insert("x-aegis-ref".to_owned(), Value::Bool(true));
    wrapper.insert(
        "oneOf".to_owned(),
        Value::Array(vec![native, env_ref_schema(), file_ref_schema()]),
    );

    *prop = Value::Object(wrapper);
}

fn extract_meta(schema: &Value) -> Map<String, Value> {
    let mut meta = Map::new();
    if let Some(obj) = schema.as_object() {
        for &key in &["title", "description", "default"] {
            if let Some(v) = obj.get(key).cloned() {
                meta.insert(key.to_owned(), v);
            }
        }
    }
    meta
}

fn extract_native(schema: &Value) -> Value {
    if let Some(any_of) = schema.get("anyOf").and_then(|a| a.as_array()) {
        let non_nulls: Vec<&Value> =
            any_of.iter().filter(|v| !is_null_type(v)).collect();
        if non_nulls.len() == 1 && any_of.len() == 2 {
            return non_nulls[0].clone();
        }
    }
    schema.clone()
}

fn is_null_type(v: &Value) -> bool {
    v.get("type") == Some(&Value::String("null".to_owned()))
}

fn is_string_type(schema: &Value) -> bool {
    if schema.get("type") == Some(&Value::String("string".to_owned())) {
        return true;
    }
    if let Some(arr) = schema.get("enum").and_then(|e| e.as_array()) {
        return arr.first().is_some_and(|v| v.is_string());
    }
    false
}

fn add_negative_lookahead(schema: &mut Value) {
    if let Some(obj) = schema.as_object_mut() {
        obj.insert(
            "pattern".to_owned(),
            Value::String("^(?!env:)(?!file:).*$".to_owned()),
        );
    }
}

fn fix_integer_formats(schema: &mut Value) {
    let Some(obj) = schema.as_object_mut() else {
        return;
    };
    if obj.get("type") != Some(&Value::String("integer".to_owned())) {
        return;
    }
    let format = obj.get("format").and_then(|f| f.as_str()).unwrap_or("");
    match format {
        "uint16" => {
            obj.remove("format");
            obj.insert("minimum".to_owned(), serde_json::json!(0));
            obj.insert("maximum".to_owned(), serde_json::json!(65535));
        }
        "uint32" => {
            obj.remove("format");
            obj.insert("minimum".to_owned(), serde_json::json!(0));
            obj.insert("maximum".to_owned(), serde_json::json!(4294967295u64));
        }
        "uint64" | "uint" => {
            obj.remove("format");
            obj.insert("minimum".to_owned(), serde_json::json!(0));
        }
        _ => {}
    }
}

fn strip_meta(schema: &mut Value) {
    if let Some(obj) = schema.as_object_mut() {
        obj.remove("title");
        obj.remove("description");
        obj.remove("default");
    }
}

fn env_ref_schema() -> Value {
    serde_json::json!({
        "type": "string",
        "pattern": "^env:.+"
    })
}

fn file_ref_schema() -> Value {
    serde_json::json!({
        "type": "string",
        "pattern": "^file:.+"
    })
}

fn obj_mut<'a>(
    v: &'a mut Value,
    key: &str,
) -> Option<&'a mut Map<String, Value>> {
    v.get_mut(key)?.as_object_mut()
}
