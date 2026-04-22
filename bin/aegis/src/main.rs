use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "aegis", version, about = "Aegis Authentication & Identity Platform CLI")]
struct Cli {
    #[arg(long, global = true, default_value = "aegis.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    Migrate {
        #[command(subcommand)]
        action: MigrateAction,
    },
    Schema {
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    Init,
    Validate,
    Show,
    #[command(name = "env-export")]
    EnvExport {
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Diff {
        #[arg(long)]
        endpoint: Option<String>,
    },
    Dump {
        #[arg(long, default_value = "default", help = "Dump mode: default or current")]
        mode: String,
        #[arg(help = "Target path, or \"-\" for stdout [default: ./aegis.toml]")]
        target: Option<String>,
    },
}

#[derive(Subcommand)]
enum MigrateAction {
    Up,
    Status,
    Create {
        name: String,
    },
}

fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(cli) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Commands::Config { action } => run_config(action, &cli.config),
        Commands::Migrate { action } => run_migrate(action, &cli.config),
        Commands::Schema { out } => run_schema(out),
    }
}

fn run_config(
    action: ConfigAction,
    config_path: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        ConfigAction::Init => {
            let source = aegis_config::ConfigSrc::default();
            let toml = source.to_toml()?;
            std::fs::write(config_path, toml)?;
            println!("config written to {}", config_path.display());

            let env_path = config_path
                .parent()
                .unwrap_or(std::path::Path::new("."))
                .join(".env.aegis");
            let template = aegis_config::Config::default_env_template();
            std::fs::write(&env_path, template)?;
            println!("env template written to {}", env_path.display());
        }
        ConfigAction::Validate => {
            aegis_config::Config::load(Some(config_path))?;
            println!("config is valid");
        }
        ConfigAction::Show => {
            let config = aegis_config::Config::load(Some(config_path))?;
            println!("{}", config.to_toml()?);
        }
        ConfigAction::EnvExport { out } => {
            let config = aegis_config::Config::load(Some(config_path))?;
            let env_path = out
                .as_deref()
                .unwrap_or(std::path::Path::new(".env.aegis"));
            aegis_config::dump_env_resolved(&config, env_path)?;
            println!("env written to {}", env_path.display());
        }
        ConfigAction::Diff { endpoint } => {
            eprintln!(
                "config diff requires a running instance at {} (not yet implemented)",
                endpoint.as_deref().unwrap_or("http://localhost:8080")
            );
            std::process::exit(1);
        }
        ConfigAction::Dump { mode, target } => {
            let dump_mode = match mode.as_str() {
                "default" => aegis_config::DumpMode::Default,
                "current" => aegis_config::DumpMode::Current,
                other => {
                    eprintln!("unknown mode: {other} (expected: default, current)");
                    std::process::exit(1);
                }
            };

            let dump_target = match target.as_deref() {
                Some("-") => aegis_config::DumpTarget::Stdout,
                Some(p) => aegis_config::DumpTarget::File(PathBuf::from(p)),
                None => aegis_config::DumpTarget::DefaultFile,
            };

            let source = if matches!(dump_mode, aegis_config::DumpMode::Current) {
                Some(aegis_config::ConfigSrc::from_file(config_path)?)
            } else {
                None
            };

            let opts = aegis_config::DumpOptions {
                mode: dump_mode,
                target: dump_target,
                env_file: None,
            };

            aegis_config::dump(&opts, source.as_ref())?;
        }
    }
    Ok(())
}

fn run_migrate(
    action: MigrateAction,
    config_path: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Runtime::new()?;

    match action {
        MigrateAction::Up => rt.block_on(async {
            let config = aegis_config::Config::load(Some(config_path))?;
            let db_url = config
                .database
                .as_ref()
                .ok_or("missing database config")?
                .url
                .clone();

            let pool = sqlx::PgPool::connect(&db_url).await?;
            let runner = aegis_migrate::MigrationRunner::new(pool, "migrations");
            runner.up().await?;
            println!("migrations applied");
            Ok(())
        }),
        MigrateAction::Status => rt.block_on(async {
            let config = aegis_config::Config::load(Some(config_path))?;
            let db_url = config
                .database
                .as_ref()
                .ok_or("missing database config")?
                .url
                .clone();

            let pool = sqlx::PgPool::connect(&db_url).await?;
            let runner = aegis_migrate::MigrationRunner::new(pool, "migrations");
            let status = runner.status().await?;

            for (migration, applied) in &status {
                let marker = if *applied { "applied" } else { "pending" };
                println!("  [{marker}] {} — {}", migration.version, migration.name);
            }

            Ok(())
        }),
        MigrateAction::Create { name } => {
            let dir = PathBuf::from("migrations");
            let path = aegis_migrate::MigrationRunner::create(&name, &dir)?;
            println!("created migration: {}", path.display());
            Ok(())
        }
    }
}

fn run_schema(out: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    use schemars::schema_for;

    let schema = schema_for!(aegis_config::ConfigSrc);
    let json = serde_json::to_string_pretty(&schema)?;

    match out {
        Some(path) => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&path, &json)?;
            println!("schema written to {}", path.display());
        }
        None => println!("{json}"),
    }

    Ok(())
}
