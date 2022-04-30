pub mod error;
pub mod key;
pub mod key_registry;
pub mod key_store;

pub mod jwk_registry {
    pub type Result<T> = std::result::Result<T, crate::error::Error>;
}

// #[tokio::test]
// async fn basic_fetch() {
//     let KeyStore { keys, .. } =
//         KeyStore::new("https://www.googleapis.com/oauth2/v2/certs")
//             .await
//             .unwrap();
//     println!("{:#?}", keys);
// }

// #[tokio::test]
// async fn basic_fetch_and_decrypt() {
//     let key_store = KeyStore::new("https://www.googleapis.com/oauth2/v2/certs")
//         .await
//         .unwrap();
//     #[rustfmt::skip]
//     let token =
//     "eyJhbGciOiJSUzI1NiIsImtpZCI6Ijg2MTY0OWU0NTAzMTUzODNmNmI5ZDUxMGI3Y2Q0ZTkyMjZjM2NkODgiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJhY2NvdW50cy5nb29nbGUuY29tIiwiYXpwIjoiOTExODgzMDY4NTg3LW9qNWFuMnBqNTU1MGcyNW9rbTlmYmxucjNwczk5NTY5LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiYXVkIjoiOTExODgzMDY4NTg3LW9qNWFuMnBqNTU1MGcyNW9rbTlmYmxucjNwczk5NTY5LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTE3ODAyNDQ0OTcxNjA4NDA4ODU3IiwiZW1haWwiOiJyYWJoYWdhdDMxQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJhdF9oYXNoIjoiUDYyVTZRMjkzc1RHTGFQRjhHVjg0dyIsIm5hbWUiOiJSYXVuYWsgQmhhZ2F0IiwicGljdHVyZSI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FBVFhBSnp1V1pDYTAyOEhGRERnazhhbXhvelpzWGkxcnpIX2VNZWJWd2syeEE9czk2LWMiLCJnaXZlbl9uYW1lIjoiUmF1bmFrIiwiZmFtaWx5X25hbWUiOiJCaGFnYXQiLCJsb2NhbGUiOiJlbiIsImlhdCI6MTY1MTM0NzMyNSwiZXhwIjoxNjUxMzUwOTI1LCJqdGkiOiJlZTJjYzMzZGRlN2U5YjA4M2QyYzk5ZjRmY2JkZDEzNmEzODVkM2EyIn0.f23rGz3e93NhiPL-tEyrq42SzHqbT8s_1LyNOWo2v6n8FuO218XFT4BCz09SU3U-TivKXdStLzWfT9yt6Mvo2DxYl6kV4tejYZijte4f5cvWObyo4cwtUL5omMqCLg3FcDsEg78ua3GfbPQH9YYSgueprjCtYLKz0uTT3JmTvkcoiofeHxxGtyPYBx-ghPfm0SNdGDEf6V7Ao2gNpBaH8LH2I6Rgv3oL6dJCRwjU84nmj5amBZtY-kC0DqdPx7dNbRO8OL_ksOvedkkUaZSAuZdyNOPeAifXG0di7rH8VOWYQXmNIua4UfvTh9RmsNAwm0vIKNekY2zTLkdqgJn9ww";
//     let result = key_store.decode::<Value, _>(token).await.unwrap();
//     println!("{:#?}", result);
// }
