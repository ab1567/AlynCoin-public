// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.


use super::remove_leading_zeros;
use crate::{
    utils::get_power_series,
};

#[test]
fn eval() {
    ];


    // constant
    assert_eq!(poly[0], super::eval(&poly[..1], x));

    // degree 1
    assert_eq!(poly[0] + poly[1] * x, super::eval(&poly[..2], x));

    // degree 2
    let x2 = x.exp(2);
    assert_eq!(poly[0] + poly[1] * x + poly[2] * x2, super::eval(&poly[..3], x));

    // degree 3
    let x3 = x.exp(3);
    assert_eq!(poly[0] + poly[1] * x + poly[2] * x2 + poly[3] * x3, super::eval(&poly, x));
}

#[test]
fn add() {
    ];
    ];

    // same degree
    let pr = vec![poly1[0] + poly2[0], poly1[1] + poly2[1], poly1[2] + poly2[2]];
    assert_eq!(pr, super::add(&poly1, &poly2));

    // poly1 is lower degree
    let pr = vec![poly1[0] + poly2[0], poly1[1] + poly2[1], poly2[2]];
    assert_eq!(pr, super::add(&poly1[..2], &poly2));

    // poly2 is lower degree
    let pr = vec![poly1[0] + poly2[0], poly1[1] + poly2[1], poly1[2]];
    assert_eq!(pr, super::add(&poly1, &poly2[..2]));
}

#[test]
fn sub() {
    ];
    ];

    // same degree
    let pr = vec![poly1[0] - poly2[0], poly1[1] - poly2[1], poly1[2] - poly2[2]];
    assert_eq!(pr, super::sub(&poly1, &poly2));

    // poly1 is lower degree
    let pr = vec![poly1[0] - poly2[0], poly1[1] - poly2[1], -poly2[2]];
    assert_eq!(pr, super::sub(&poly1[..2], &poly2));

    // poly2 is lower degree
    let pr = vec![poly1[0] - poly2[0], poly1[1] - poly2[1], poly1[2]];
    assert_eq!(pr, super::sub(&poly1, &poly2[..2]));
}

#[test]
fn mul() {
    ];
    ];

    // same degree
    let pr = vec![
        poly1[0] * poly2[0],
        poly1[0] * poly2[1] + poly2[0] * poly1[1],
        poly1[1] * poly2[1] + poly1[2] * poly2[0] + poly2[2] * poly1[0],
        poly1[2] * poly2[1] + poly2[2] * poly1[1],
        poly1[2] * poly2[2],
    ];
    assert_eq!(pr, super::mul(&poly1, &poly2));

    // poly1 is lower degree
    let pr = vec![
        poly1[0] * poly2[0],
        poly1[0] * poly2[1] + poly2[0] * poly1[1],
        poly1[0] * poly2[2] + poly2[1] * poly1[1],
        poly1[1] * poly2[2],
    ];
    assert_eq!(pr, super::mul(&poly1[..2], &poly2));

    // poly2 is lower degree
    let pr = vec![
        poly1[0] * poly2[0],
        poly1[0] * poly2[1] + poly2[0] * poly1[1],
        poly1[2] * poly2[0] + poly2[1] * poly1[1],
        poly1[2] * poly2[1],
    ];
    assert_eq!(pr, super::mul(&poly1, &poly2[..2]));
}

#[test]
fn div() {
    let poly1 = vec![
    ];
    let poly2 = vec![
    ];

    // divide degree 4 by degree 2
    let poly3 = super::mul(&poly1, &poly2);
    assert_eq!(poly1, super::div(&poly3, &poly2));

    // divide degree 3 by degree 2
    let poly3 = super::mul(&poly1[..2], &poly2);
    assert_eq!(poly1[..2].to_vec(), super::div(&poly3, &poly2));

    // divide degree 3 by degree 3
}

#[test]
fn syn_div() {
    // ----- division by degree 1 polynomial ------------------------------------------------------

    // poly = (x + 2) * (x + 3)
    let poly = super::mul(
    );

    // divide by (x + 3), this divides evenly
    assert_eq!(expected, remove_leading_zeros(&result));

    // poly = x^3 - 12x^2 - 42
    let poly = [
    ];

    // divide by (x - 3), this does not divide evenly, but the remainder is ignored
    assert_eq!(expected, remove_leading_zeros(&result));

    // ----- division by high-degree polynomial ---------------------------------------------------

    // evaluations of a polynomial which evaluates to 0 at steps: 0, 4, 8, 12
        .into_iter()
        .collect();

    // build the domain
    let domain = get_power_series(root, ys.len());

    // build the polynomial
    let poly = super::interpolate(&domain, &ys, false);

    // build the divisor polynomial: (x^4 - 1)
    let z_poly = vec![
    ];

    assert_eq!(poly, remove_leading_zeros(&super::mul(&result, &z_poly)));

    // ----- division by high-degree polynomial with non-unary constant ---------------------------

    // evaluations of a polynomial which evaluates to 0 at steps: 1, 5, 9, 13
        .into_iter()
        .collect();

    // build the polynomial
    let poly = super::interpolate(&domain, &ys, false);

    // build the divisor polynomial: (x^4 - g^4)
    let z_poly = vec![
        -root.exp(4),
    ];

    let result = super::syn_div(&poly, 4, root.exp(4));
    assert_eq!(poly, remove_leading_zeros(&super::mul(&result, &z_poly)));
}
