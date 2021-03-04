// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
#![allow(non_camel_case_types)]

//! Specification-defined types

pub type psa_status_t = i32;
pub type psa_key_type_t = u16;
pub type psa_ecc_family_t = u8;
pub type psa_dh_family_t = u8;
pub type psa_algorithm_t = u32;
pub type psa_key_lifetime_t = u32;
pub type psa_key_persistence_t = u8;
pub type psa_key_location_t = u32;
pub type psa_key_id_t = u32;
pub type psa_key_usage_t = u32;
pub type psa_key_derivation_step_t = u16;
