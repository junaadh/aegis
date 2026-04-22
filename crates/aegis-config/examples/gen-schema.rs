fn main() {
    let schema = aegis_config::generate_schema();
    println!("{}", serde_json::to_string_pretty(&schema).unwrap());
}
