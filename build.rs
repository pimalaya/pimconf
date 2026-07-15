//! Build script baking feature, target and git metadata into the CLI
//! binary through the pimalaya-cli build helpers.

#[cfg(feature = "cli")]
fn main() {
    use pimalaya_cli::build::{features_env, git_envs, target_envs};

    features_env(include_str!("./Cargo.toml"));
    target_envs();
    git_envs();
}

#[cfg(not(feature = "cli"))]
fn main() {
    // NOTE: nothing to do without the CLI binary.
}
