pub trait Dialer {
    type C;

    fn load_from_config(config: Self::C) -> Self;
}

pub fn load_dialer<D>(config: D::C) -> D
where
    D: Dialer,
{
    D::load_from_config(config)
}
