// SPDX-License-Identifier: LGPL-2.1-or-later

//! systemd-networkd as Kestrel's L3 provider.
//!
//! Kestrel never configures IP itself. For each bound link, this adapter
//! writes a runtime `.network` unit and asks networkd to reload and
//! reconfigure that link. Readiness, addresses, and DHCP leases are read
//! back from networkd's `Describe()` JSON. DNS learned on the link flows to
//! systemd-resolved through networkd, as on any networkd system.
//!
//! **Ownership tag.** Units are named `<prefix><link>.network` (default
//! prefix `10-kestrel-`) in the runtime unit directory. `sweep` removes
//! every such file. So the unit files themselves record what Kestrel owns,
//! and a crash cannot leak configuration past the next start.
//!
//! **Precedence.** networkd uses the first matching `.network` file in
//! lexical order across `/etc`, `/run`, and `/usr/lib`. The `10-` prefix
//! wins over typical catch-all units (`80-wifi-station.network`,
//! `99-default.network`), but an administrator's lower-numbered match in
//! `/etc` takes precedence by design. Use profile `l3 = unmanaged` for
//! links the administrator configures.

mod describe;
mod provider;
mod unit;

pub use describe::parse_link_status;
pub use provider::{Networkd, NetworkdConfig};
pub use unit::render;
