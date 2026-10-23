# PS5 Pro 11.60 Linux test 1

This is the first controlled Linux boot test for a retail PS5 Pro on exact
firmware 11.60 (`0x11600005`). The loader passed the complete six-target CI
build and source review, but this exact Pro Linux path has not yet booted on
hardware. Treat it as experimental.

Do not use the older Run 18 or Run 21 loaders on a PS5 Pro. Do not use any CI
artifact from loader commit `96a5fab`. Use only the ELF linked below and verify
its checksum before sending it.

## Downloads

- Loader ELF: [ps5-linux-loader-1160-dma-e820-bounded.elf](https://github.com/gzimbric/ps5-linux-loader/releases/download/firmware-11.60-pro-linux-test-1/ps5-linux-loader-1160-dma-e820-bounded.elf)
- Ubuntu Image 3: [ps5-ubuntu2404-k73.img.xz](https://github.com/gzimbric/ps5-linux-image/releases/download/ubuntu2404-k73-image-3/ps5-ubuntu2404-k73.img.xz)
- Full Ubuntu release notes: [ubuntu2404-k73-image-3](https://github.com/gzimbric/ps5-linux-image/releases/tag/ubuntu2404-k73-image-3)

SHA-256:

```text
31625e04aaac83fffbf8b1b4f8c012114a0cc85336c6a4c8c6cd9bc9ef492f4b  ps5-linux-loader-1160-dma-e820-bounded.elf
9f038b316be5595b5b1629a86470cd7b955cf977741e022d9e1135898746de04  ps5-ubuntu2404-k73.img.xz
```

On Windows, verify a download in PowerShell with:

```powershell
(Get-FileHash .\ps5-linux-loader-1160-dma-e820-bounded.elf -Algorithm SHA256).Hash.ToLower()
(Get-FileHash .\ps5-ubuntu2404-k73.img.xz -Algorithm SHA256).Hash.ToLower()
```

## Prepare the USB drive

1. Flash `ps5-ubuntu2404-k73.img.xz` with balenaEtcher or Raspberry Pi Imager.
   Flashing erases the selected drive, so verify the drive before starting.
2. Unplug and reconnect the drive. Ignore or cancel any request to format the
   Linux partition. Open the small FAT boot partition.
3. Open `cmdline.txt` in a plain-text editor. Keep its existing contents on one
   line and append one space followed by this temporary first-boot profile:

   ```text
   systemd.unit=multi-user.target systemd.mask=ps5-performance.service systemd.mask=ps5fan.service modprobe.blacklist=amdgpu,ps5_gpufreq,ps5_cpufreq module_blacklist=amdgpu,ps5_gpufreq,ps5_cpufreq
   ```

4. Save as plain text without changing the filename, then safely eject the
   drive. Do not add `nokaslr`, `mem=` or `memmap=`.

The temporary profile intentionally disables the graphical desktop and the
unvalidated Pro GPU, clock-scaling and fan-policy paths. A black HDMI screen is
expected for this first test. The milestone is Linux over wired SSH.

## Boot procedure

1. Fully power off the PS5 Pro. Do not begin from Rest Mode, and do not reuse a
   GameOS boot after a failed loader attempt.
2. Connect the flashed Ubuntu USB drive and wired Ethernet before powering on.
3. Boot GameOS normally. Do not load etaHEN, kstuff or another payload that
   changes the same kernel or hypervisor state.
4. Run the kernel exploit. After it reports success, send exactly
   `ps5-linux-loader-1160-dma-e820-bounded.elf` with the usual payload sender.
5. The loader should put the console into Rest Mode automatically. Wait until
   the orange light stops blinking and is solid. Do not wake it early.
6. Press the console power button once to wake it. The light should eventually
   turn white. HDMI may remain black because the first-boot profile blacklists
   `amdgpu`.
7. Wait up to three minutes, find the console's wired address in the router's
   DHCP/client list, and connect:

   ```text
   ssh ps5@CONSOLE_IP
   ```

   The temporary login is `ps5` with password `ubuntu`.

If the loader displays a refusal, freezes before solid orange, returns to
GameOS, pulses blue indefinitely or powers off, photograph the exact message
and note the LED timeline. Fully power off before any retry. Do not send the
loader a second time in the same GameOS boot.

## Collect the result

Once SSH works, run:

```bash
uname -a
cat /proc/cmdline
ip -brief address
lspci -nnk
systemctl --failed --no-pager
sudo systemctl start ps5-boot-report.service || true
sudo journalctl -b --no-pager > /home/ps5/ps5-pro-first-boot-journal.txt
sudo dmesg > /home/ps5/ps5-pro-first-boot-dmesg.txt
sudo sync
```

Copy these files back before changing any of the temporary gates:

- `/boot/efi/ps5-boot-report.txt`
- `/home/ps5/ps5-pro-first-boot-journal.txt`
- `/home/ps5/ps5-pro-first-boot-dmesg.txt`

The boot report removes Wi-Fi names and MAC addresses but retains IP addresses.
Review it before posting publicly; send the first Pro result privately.

When collection is complete, shut down Linux with:

```bash
sudo poweroff
```

Wait until the console is fully off. Do not use Linux suspend or Rest Mode.
Leave the temporary `cmdline.txt` gates in place until the headless baseline is
reviewed. Display, fan policy and frequency scaling should be enabled one at a
time in later boots.
