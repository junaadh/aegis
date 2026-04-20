use time::OffsetDateTime;

pub trait Anonymize {
    type Err;

    fn deleted_at(&self) -> Option<OffsetDateTime>;
    fn anonymize_after(&self) -> Option<OffsetDateTime>;
    fn anonymized_at(&self) -> Option<OffsetDateTime>;

    fn should_anonymize_at(&self, now: OffsetDateTime) -> bool {
        matches!(
            (self.deleted_at(), self.anonymized_at(), self.anonymize_after()),
            (Some(_), None, Some(when)) if now >= when
        )
    }

    fn anonymize(&mut self, at: OffsetDateTime) -> Result<(), Self::Err>;
}
