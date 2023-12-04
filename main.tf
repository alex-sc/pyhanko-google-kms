terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "4.51.0"
    }
  }
}

provider "google" {
  credentials = file("~/alex-sc.json")

  project = "alex-sc-test"
  region  = "us-central1"
  zone    = "us-central1-c"
}

resource "google_kms_key_ring" "keyring" {
  name     = "pdf-signing-keyring"
  location = "global"
}

resource "google_kms_crypto_key" "asymmetric-sign-key" {
  name     = "pdf-signing-key"
  key_ring = google_kms_key_ring.keyring.id
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm = "RSA_SIGN_PKCS1_2048_SHA256"
//    protection_level = "HSM"
  }

  lifecycle {
    prevent_destroy = true
  }
}
