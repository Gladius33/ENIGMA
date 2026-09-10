use aws_config::BehaviorVersion;
use aws_credential_types::Credentials;
use aws_sdk_s3::{config::Builder as S3ConfigBuilder, Client as S3Client};
use aws_types::region::Region;

use crate::config::S3Config;

pub async fn build_s3_client(config: &S3Config) -> S3Client {
    let shared_config = aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new(config.region.clone()))
        .credentials_provider(Credentials::new(
            config.access_key_id.clone(),
            config.secret_access_key.clone(),
            None,
            None,
            "env",
        ))
        .endpoint_url(config.endpoint.clone())
        .load()
        .await;

    let s3_config = S3ConfigBuilder::from(&shared_config)
        .force_path_style(config.force_path_style)
        .build();

    S3Client::from_conf(s3_config)
}
