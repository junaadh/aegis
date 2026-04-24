use aegis_config::{Config, JwtAlgorithm};
use aegis_core::{
    JwtClaims, ServiceAuthError, ServicePrincipal, ServiceTokenScope,
};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

pub struct JwtIssuer {
    algorithm: Algorithm,
    issuer: String,
    audience: String,
    encoding_key: EncodingKey,
}

pub struct JwtVerifier {
    validation: Validation,
    decoding_key: DecodingKey,
}

impl JwtIssuer {
    pub fn from_config(
        config: &Config,
    ) -> Result<Option<Self>, ServiceJwtError> {
        if !config.crypto.jwt.enabled {
            return Ok(None);
        }

        let algorithm = jwt_algorithm(config.crypto.jwt.algorithm)?;
        let issuer = required_claim(
            config.crypto.jwt.issuer.as_deref(),
            "crypto.jwt.issuer",
        )?;
        let audience = required_claim(
            config.crypto.jwt.audience.as_deref(),
            "crypto.jwt.audience",
        )?;
        let private_key = required_claim(
            config.crypto.jwt.private_key.as_deref(),
            "crypto.jwt.private_key",
        )?;

        let encoding_key = match algorithm {
            Algorithm::RS256 => {
                EncodingKey::from_rsa_pem(private_key.as_bytes())?
            }
            Algorithm::ES256 => {
                EncodingKey::from_ec_pem(private_key.as_bytes())?
            }
            _ => {
                return Err(ServiceJwtError::UnsupportedAlgorithm(
                    config.crypto.jwt.algorithm,
                ));
            }
        };

        Ok(Some(Self {
            algorithm,
            issuer,
            audience,
            encoding_key,
        }))
    }

    pub fn issue_service_token<I>(
        &self,
        subject: impl Into<String>,
        scopes: I,
        ttl: Duration,
        now: OffsetDateTime,
    ) -> Result<String, ServiceJwtError>
    where
        I: IntoIterator<Item = ServiceTokenScope>,
    {
        if ttl.is_zero() || ttl.is_negative() {
            return Err(ServiceJwtError::InvalidTtl);
        }

        let claims = JwtClaims::new_service(
            self.issuer.clone(),
            self.audience.clone(),
            subject,
            scopes,
            now,
            now + ttl,
            Uuid::now_v7(),
        );

        let mut header = Header::new(self.algorithm);
        header.typ = Some("JWT".to_owned());

        jsonwebtoken::encode(&header, &claims, &self.encoding_key)
            .map_err(Into::into)
    }
}

impl JwtVerifier {
    pub fn from_config(
        config: &Config,
    ) -> Result<Option<Self>, ServiceJwtError> {
        if !config.crypto.jwt.enabled {
            return Ok(None);
        }

        let algorithm = jwt_algorithm(config.crypto.jwt.algorithm)?;
        let issuer = required_claim(
            config.crypto.jwt.issuer.as_deref(),
            "crypto.jwt.issuer",
        )?;
        let audience = required_claim(
            config.crypto.jwt.audience.as_deref(),
            "crypto.jwt.audience",
        )?;
        let public_key = required_claim(
            config.crypto.jwt.public_key.as_deref(),
            "crypto.jwt.public_key",
        )?;

        let decoding_key = match algorithm {
            Algorithm::RS256 => {
                DecodingKey::from_rsa_pem(public_key.as_bytes())?
            }
            Algorithm::ES256 => {
                DecodingKey::from_ec_pem(public_key.as_bytes())?
            }
            _ => {
                return Err(ServiceJwtError::UnsupportedAlgorithm(
                    config.crypto.jwt.algorithm,
                ));
            }
        };

        let mut validation = Validation::new(algorithm);
        validation.set_issuer(&[issuer.as_str()]);
        validation.set_audience(&[audience.as_str()]);

        Ok(Some(Self {
            validation,
            decoding_key,
        }))
    }

    pub fn verify_service_token(
        &self,
        token: &str,
    ) -> Result<ServicePrincipal, ServiceJwtError> {
        let claims = jsonwebtoken::decode::<JwtClaims>(
            token,
            &self.decoding_key,
            &self.validation,
        )
        .map_err(ServiceJwtError::from)?
        .claims;

        claims
            .service_principal()
            .map_err(ServiceJwtError::InvalidClaims)
    }
}

fn required_claim(
    value: Option<&str>,
    field: &'static str,
) -> Result<String, ServiceJwtError> {
    let value = value.unwrap_or_default().trim();
    if value.is_empty() {
        return Err(ServiceJwtError::MissingConfig(field));
    }
    Ok(value.to_owned())
}

fn jwt_algorithm(
    algorithm: JwtAlgorithm,
) -> Result<Algorithm, ServiceJwtError> {
    match algorithm {
        JwtAlgorithm::RS256 => Ok(Algorithm::RS256),
        JwtAlgorithm::ES256 => Ok(Algorithm::ES256),
        JwtAlgorithm::HS256 => {
            Err(ServiceJwtError::UnsupportedAlgorithm(algorithm))
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ServiceJwtError {
    #[error("missing jwt config: {0}")]
    MissingConfig(&'static str),
    #[error("unsupported jwt algorithm: {0:?}")]
    UnsupportedAlgorithm(JwtAlgorithm),
    #[error("service token ttl must be greater than zero")]
    InvalidTtl,
    #[error("invalid service token claims: {0}")]
    InvalidClaims(#[from] ServiceAuthError),
    #[error("jwt error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::AdminReadUser;

    const RSA_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC0A9uJCir7yaHM\nKmH8EvJIWZPCW2vBmBCNpHdg31ZaT/HVGYQIATjVlhS84FwwyyCGhJOxe84sRzY0\nFmb3m0CUo9ay67vzr/ncLcBXGxoGPBtzo5fcIg58McfOzCE5ULV3SnnwsgNQmSH0\nN0FtJxmIHEtd97agzxKVFb0+kus4/zCiaM9AeGCCT4jsVxKdecTu1l4PMy7lOhW1\neYq9SRFm0ja3yJMx3jZNRvmDjppVVIvNEWFXWM/ixPbKxXR8RqPYISS1lo073H9c\nGrIqyXhXwUNUm2i8L2+qC8WvGAuKyCeeNihN5UN/B+su6XXCs1XzXFpICU16ccmw\ns4Vx+h77AgMBAAECggEAMfImDcpH7c9eeH7D7AQ3u/I6qIDkD3VJFnus8bBVzb4D\nq6wmMXBhXAWFoHghrBoX3qrXLbXbmPZzKBWVIRsu2m7w6Xi1j+HiEgCRrrliyZsQ\nxM99mYLLgRLwzMRfbX8iskP0PF+vwsOSI6fXG9lu4JB1Ks/JmKmLjtjWxo9N+2R/\nV+Zu7Xx7OamadQeCoOYbP4UOa+YnnQ3GZ/U5d4fAHRgw6uL90wC2TSl3iIR8Wnm4\nR4Em4l4zDDJ8zbnF4//TRPkI48IbehwA0yadQSaPSRA7RVfWxMlviWyNgiW2+Lg2\nZh5PHY++HpGQSMscefoO4NRdxH1du0f1HuXVNbcbbQKBgQDf1WIAYzbcFJZ+lYNA\nUNGKlLNNzXvKhM6eMuDOLaScffZQL+aafrjIXKd/tU3N6p1IV0u9xlID7uyj+qgh\nroPe5rvQOEH69YQ521Qu5NgjzZJXpAcvRJgj4TtmIN9lZPouH5G6J5zNxOYYwR/0\n4XCFwSluM+r2qVrdVJL4WbFifQKBgQDN4m+3yIwlP18BY+n+Qu63yNORp5a46MQ5\n/z2T+5LdAnpZWwWvqNqq0zVyRhc51kh7UGpIqPrzXgarqR2Pp7P7ntO3S/o/Bj6p\nzCkiqVV5ELKtsXNJKcLWPkynZ0Mr0ZyDs1toZnSr5cQ2/Otvs+KGKGWOCr1+5ZB5\nHRrBmcaI1wKBgHne8dwqKP2NTB+iAnOrTVv5+OKcxhEPXHxwUUyRN3ZpcwpX+mQW\nKUAWirCTI8jBPF/eAARVDeTMWxYxbQfhwDVGRe5qIyqkMRlbXSunODPOQybqzWqk\nG341rSS/M0M+xqUEVVEZLlwvH+VMibzIXn7FHGy/Yehpb2rhGKCWHWn1AoGBAMdd\nq90FwGAZO4B3JhFm8w7Y07bJ2DP6gnm+5fw0soR9b8izUZBGLGka2ThtEvSYwdtX\nhXQS3d9of4Ee5FdFiA3yQQXP9uWswGVgI71CyFfRiZSUrxR78gXQkh3Q6sS115/Y\nwH0aKYSDnDu7MqkaQhKzb5PaZqFI31vIiS5MIGpFAoGBAMbbKA2C7eVMs7JuokDT\n+vlJU+m90y5Xtc9JsiBt8suJoSokhw1lx8rKIEQ/AHKBq0/dChihXGfMREdvqHUX\nZTSfQ2lRZMYHBor6zV8CCIQa5zGI6l7lZCsZwy2zmY3LsUFCgxG1GROdZlGhIfFu\nOthpzeUl0+8iqB1j6SGr3JU6\n-----END PRIVATE KEY-----\n";
    const RSA_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtAPbiQoq+8mhzCph/BLy\nSFmTwltrwZgQjaR3YN9WWk/x1RmECAE41ZYUvOBcMMsghoSTsXvOLEc2NBZm95tA\nlKPWsuu786/53C3AVxsaBjwbc6OX3CIOfDHHzswhOVC1d0p58LIDUJkh9DdBbScZ\niBxLXfe2oM8SlRW9PpLrOP8womjPQHhggk+I7FcSnXnE7tZeDzMu5ToVtXmKvUkR\nZtI2t8iTMd42TUb5g46aVVSLzRFhV1jP4sT2ysV0fEaj2CEktZaNO9x/XBqyKsl4\nV8FDVJtovC9vqgvFrxgLisgnnjYoTeVDfwfrLul1wrNV81xaSAlNenHJsLOFcfoe\n+wIDAQAB\n-----END PUBLIC KEY-----\n";

    fn config() -> Config {
        let mut config = Config::default();
        config.crypto.jwt.enabled = true;
        config.crypto.jwt.algorithm = JwtAlgorithm::RS256;
        config.crypto.jwt.private_key = Some(RSA_PRIVATE_KEY.to_owned());
        config.crypto.jwt.public_key = Some(RSA_PUBLIC_KEY.to_owned());
        config.crypto.jwt.issuer = Some("aegis".to_owned());
        config.crypto.jwt.audience = Some("aegis-internal".to_owned());
        config
    }

    #[test]
    fn issue_and_verify_round_trip() {
        let config = config();
        let issuer = JwtIssuer::from_config(&config).unwrap().unwrap();
        let verifier = JwtVerifier::from_config(&config).unwrap().unwrap();

        let token = issuer
            .issue_service_token(
                "service:dashboard",
                [ServiceTokenScope::from(AdminReadUser::permission())],
                Duration::days(7),
                OffsetDateTime::now_utc(),
            )
            .unwrap();

        let principal = verifier.verify_service_token(&token).unwrap();

        assert_eq!(principal.subject, "service:dashboard");
        assert!(principal.permissions.has(AdminReadUser::permission()));
    }
}
