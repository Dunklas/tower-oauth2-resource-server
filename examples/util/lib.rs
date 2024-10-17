use std::path::PathBuf;

use testcontainers::{
    core::{IntoContainerPort, Mount, WaitFor},
    runners::AsyncRunner,
    ContainerAsync, GenericImage, ImageExt, TestcontainersError,
};

pub async fn start_oidc_provider() -> ContainerAsync<GenericImage> {
    setup_keycloak()
        .await
        .expect("Failed to start oidc provider")
}

async fn setup_keycloak() -> Result<ContainerAsync<GenericImage>, TestcontainersError> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    GenericImage::new("keycloak/keycloak", "26.0")
        .with_exposed_port(8080.tcp())
        .with_wait_for(WaitFor::message_on_stdout(
            "Running the server in development mode. DO NOT use this configuration in production.",
        ))
        .with_mount(Mount::bind_mount(
            format!("{}/realm.json", root.to_str().unwrap()),
            "/opt/keycloak/data/import/realm.json",
        ))
        .with_env_var("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
        .with_env_var("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")
        .with_cmd(vec!["start-dev", "--import-realm"])
        .start()
        .await
}
