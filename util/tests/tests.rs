//! Tests for the public API of `monero-wallet-util`.

use monero_wallet_util::seed::{original, polyseed, Seed, SeedError, SeedType};

use zeroize::Zeroizing;

// The first 19 bytes are valid Polyseed entropy, which requires its final 13 bytes to be clear
// and the top two bits of its 19th byte to be unset, while the full 32 bytes form a canonical
// scalar valid as an original seed's entropy
fn valid_entropy() -> Zeroizing<[u8; 32]> {
  let mut entropy = Zeroizing::new([0; 32]);
  for (i, byte) in entropy.iter_mut().take(19).enumerate() {
    *byte = u8::try_from(i + 1).unwrap();
  }
  entropy
}

#[test]
fn test_original_seed_round_trip() {
  let seed =
    Seed::from_entropy(SeedType::Original(original::Language::English), valid_entropy(), None)
      .unwrap();

  // Original seeds don't have a birthday, and don't differentiate their key from their entropy
  assert_eq!(seed.birthday(), 0);
  assert_eq!(seed.key(), seed.entropy());

  // The string form, which includes the checksum word, must parse back to the same seed
  let parsed =
    Seed::from_string(SeedType::Original(original::Language::English), seed.to_string()).unwrap();
  assert_eq!(parsed, seed);
  assert_eq!(parsed.entropy(), seed.entropy());
  assert_eq!(parsed.entropy(), valid_entropy());
}

#[test]
fn test_polyseed_round_trip() {
  const BIRTHDAY: u64 = 1_700_000_000;
  let seed = Seed::from_entropy(
    SeedType::Polyseed(polyseed::Language::English),
    valid_entropy(),
    Some(BIRTHDAY),
  )
  .unwrap();

  // The birthday is embedded rounded down to a whole Polyseed month
  assert!(BIRTHDAY - seed.birthday() < 2_629_746);
  assert!(seed.birthday() <= BIRTHDAY);

  let parsed =
    Seed::from_string(SeedType::Polyseed(polyseed::Language::English), seed.to_string()).unwrap();
  assert_eq!(parsed, seed);
  assert_eq!(parsed.entropy(), seed.entropy());
  assert_eq!(parsed.entropy(), valid_entropy());
  assert_eq!(parsed.key(), seed.key());
  assert_eq!(parsed.birthday(), seed.birthday());
}

#[test]
fn test_invalid_entropy() {
  // All 0xff isn't a canonical scalar (as it exceeds the Ed25519 group order), and sets
  // Polyseed's reserved bytes
  let entropy = Zeroizing::new([0xff; 32]);
  assert_eq!(
    Seed::from_entropy(SeedType::Original(original::Language::English), entropy.clone(), None),
    Err(SeedError::InvalidEntropy)
  );
  assert_eq!(
    Seed::from_entropy(SeedType::Polyseed(polyseed::Language::English), entropy, None),
    Err(SeedError::InvalidEntropy)
  );
}
