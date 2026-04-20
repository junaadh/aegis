use aegis_config::Config;
use schemars::schema::{Schema, SchemaObject, SingleOrVec};
use schemars::schema_for;

fn main() {
    let mut root = schema_for!(Config);
    fix_integer_formats_obj(&mut root.schema);
    for (_, value) in root.definitions.iter_mut() {
        fix_integer_formats(value);
    }
    inject_tombi_extensions(&mut root);
    println!("{}", serde_json::to_string_pretty(&root).unwrap());
}

fn fix_integer_formats(schema: &mut Schema) {
    if let Schema::Object(obj) = schema {
        fix_integer_formats_obj(obj);
    }
}

fn fix_integer_formats_obj(obj: &mut SchemaObject) {
    if let Some(ref format) = obj.format
        && let Some(SingleOrVec::Single(it)) = &obj.instance_type
        && matches!(**it, schemars::schema::InstanceType::Integer)
    {
        match format.as_str() {
            "uint16" => {
                obj.format = None;
                let n = obj.number.get_or_insert_with(Default::default);
                n.minimum = Some(0.0);
                n.maximum = Some(65535.0);
            }
            "uint32" => {
                obj.format = None;
                let n = obj.number.get_or_insert_with(Default::default);
                n.minimum = Some(0.0);
                n.maximum = Some(4294967295.0);
            }
            "uint64" => {
                obj.format = None;
                let n = obj.number.get_or_insert_with(Default::default);
                n.minimum = Some(0.0);
            }
            "uint" => {
                obj.format = None;
                let n = obj.number.get_or_insert_with(Default::default);
                n.minimum = Some(0.0);
            }
            _ => {}
        }
    }

    if let Some(ref mut subschemas) = obj.subschemas {
        if let Some(ref mut all_of) = subschemas.all_of {
            for s in all_of.iter_mut() {
                fix_integer_formats(s);
            }
        }
        if let Some(ref mut any_of) = subschemas.any_of {
            for s in any_of.iter_mut() {
                fix_integer_formats(s);
            }
        }
        if let Some(ref mut one_of) = subschemas.one_of {
            for s in one_of.iter_mut() {
                fix_integer_formats(s);
            }
        }
    }

    if let Some(ref mut obj_valid) = obj.object {
        for (_, value) in obj_valid.properties.iter_mut() {
            fix_integer_formats(value);
        }
    }
}

fn inject_tombi_extensions(schema: &mut schemars::schema::RootSchema) {
    schema
        .schema
        .extensions
        .insert("x-tombi-toml-version".to_owned(), serde_json::json!("1.0.0"));
    schema.meta_schema = Some("http://json-schema.org/draft-07/schema#".to_owned());
}
