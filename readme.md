opal-uefi-greeter
-

This is an UEFI application written in Rust that unlocks a SED and then launches
another UEFI application from the unlocked drive - typically some bootloader or the Linux efistub.

It's designed to be a simple minimalist PBA for self-encrypting drives that does not
include a whole another little Linux nor requires warm-rebooting to launch the system
after unlocking - it's just an UEFI bootloader passthrough.

Currently, it only supports NVMe drives, SATA support is coming soon.

Also, enterprise drives are not supported, although some bits of code are in place
to soon enable that - I cannot test that myself though.

It uses the same hashing algorithm and salt as the `sedutil-cli` does, so your SED
has to be configured with it, or with the same algorithm as well.

At some point in the future, some minimalist configurable graphics interface (similar to
`lightdm-mini-greeter`) will be made as part of this project as well, currently the password
is requested just through the UEFI text I/O.

## Using it
You have to be familiar with [sedutil-cli](https://github.com/Drive-Trust-Alliance/sedutil/wiki/Encrypting-your-drive).

Run the `./build-pba.sh` script or follow the steps from it manually - make sure
you have all the programs it uses (e.g. gdisk) and have set up Rust nightly.

This will yield an .img file that you have to use with `--loadpbaimage` argument
when setting up self-encrypted drive with the link above.

This image also contains the `config` file copied from `config-example` file in this repo.
You would want to edit that (by editing `config-example` before making the image or by mounting the image)
to specify the UEFI image that will be run - either specify the image of your bootloader (e.g. `\EFI\Microsoft\Boot\bootmgfw.efi` for Windows or `\EFI\BOOT\BOOTX64.efi` to launch the default bootloader such as grub, if present on the encrypted drive) or you can have an EFISTUB setup by specifying the `vmlinuz-linux`
itself as the UEFI image and giving it kernel arguments in the `config` file.

If you have multiple SEDs - only one of them has to have the image! This is true
even without using this project I believe. Also, a reminder that this project currently only supports
NVMe drives with OPAL v2 support, no enterprise.

## License
As with most of my projects, just MIT, no idea about the Rust dual-licensing stuff.

## Socials
Follow me on [twitter](https://twitter.com/necauqua) and [twitch](https://twitch.tv/necauqua) - I do dev streams sometimes.
