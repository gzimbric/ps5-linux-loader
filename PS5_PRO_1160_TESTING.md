# PS5 Pro 11.60 Linux test 2

This is an experimental Linux boot test for a retail PS5 Pro on firmware 11.60
(`0x11600005`). Linux has not booted on a Pro yet, so every run helps.

Test 1 panicked on every Pro right after the boot file checks. Test 2 fixes
that. Don't use test 1, the Run 18 or Run 21 loaders, or any other loader on a
Pro.

## Downloads

- [ps5-linux-loader-1160-dma-e820-bounded.elf](https://github.com/gzimbric/ps5-linux-loader/releases/download/firmware-11.60-pro-linux-test-2/ps5-linux-loader-1160-dma-e820-bounded.elf)
- [Ubuntu Image 3](https://github.com/gzimbric/ps5-linux-image/releases/download/ubuntu2404-k73-image-3/ps5-ubuntu2404-k73.img.xz)

```text
70ee361202fa7e233294b00cb0c37d496be33bf9235e2fb872d5eca8290f4564  ps5-linux-loader-1160-dma-e820-bounded.elf
9f038b316be5595b5b1629a86470cd7b955cf977741e022d9e1135898746de04  ps5-ubuntu2404-k73.img.xz
```

Check a file with `shasum -a 256 FILE` on Mac or Linux, or
`Get-FileHash FILE -Algorithm SHA256` in PowerShell on Windows.

## 1. Flash the USB drive

Flash `ps5-ubuntu2404-k73.img.xz` with balenaEtcher or Raspberry Pi Imager and
let it finish the verify step. If your computer offers to format the drive
afterwards, say no.

## 2. Edit cmdline.txt

The first boot runs without the desktop and without the Pro GPU driver, so the
screen stays black and you reach Linux over wired Ethernet with SSH.

`cmdline.txt` is on the small FAT partition named `boot`. Mac and Windows hide
that partition, so open it like this.

**Mac.** In Terminal run `diskutil list external`, find the roughly 500 MB
partition on the USB drive (for example `disk4s2`), then run
`sudo diskutil mount disk4s2`. The `boot` volume shows up in Finder.

**Windows.** Open Command Prompt as administrator and run `diskpart`, then
`list disk`, `select disk N` (your USB drive), `list partition`,
`select partition N` (the roughly 500 MB one), `assign letter=Z` and `exit`.
Edit the file with `notepad Z:\cmdline.txt` from the same window. Explorer may
still say access denied, which is fine.

**Linux.** Mount the partition labeled `boot`.

Add this to the end of the existing line, with one space before it. Keep
everything on one line.

```text
systemd.unit=multi-user.target systemd.mask=ps5-performance.service systemd.mask=ps5fan.service modprobe.blacklist=amdgpu,ps5_gpufreq,ps5_cpufreq module_blacklist=amdgpu,ps5_gpufreq,ps5_cpufreq
```

Don't add `nokaslr`, `mem=` or `memmap=`. Save, then eject the drive.

## 3. Run the loader

1. Fully power off the PS5 Pro. Don't start from Rest Mode.
2. Plug in the USB drive and an Ethernet cable, then power on.
3. Run your jailbreak and elfldr only. No etaHEN, kstuff or other payloads.
4. Send the ELF once, in a way that shows its output, and save that output.
   On Mac or Linux, install `socat` and run this.

   ```bash
   socat -t 9999999 - TCP:PS5_IP:9021 < ps5-linux-loader-1160-dma-e820-bounded.elf | tee loader-output.txt
   ```

   On Windows, install Nmap for `ncat` and run this.

   ```text
   ncat PS5_IP 9021 < ps5-linux-loader-1160-dma-e820-bounded.elf > loader-output.txt
   ```

   A payload sender app also works, but then only the on-screen messages are
   visible, so take photos.
5. The loader puts the console into Rest Mode by itself. Wait for a solid
   orange light, then press the power button once.
6. The light should turn white. Give it up to three minutes, find the console's
   address in your router's client list, and connect with `ssh ps5@CONSOLE_IP`.
   The password is `ubuntu`.

Never send the loader twice in the same boot. If anything goes wrong, fully
power off before trying again.

## 4. Send back the results

Send these privately, not in a public channel.

- `loader-output.txt` or photos of the on-screen messages
- What the light did after you pressed the power button
- Your console model (the CFI number on the back)

If SSH works, also run this and send the three files it lists.

```bash
sudo systemctl start ps5-boot-report.service
sudo journalctl -b --no-pager > ~/journal.txt
sudo dmesg > ~/dmesg.txt
ls /boot/efi/ps5-boot-report.txt ~/journal.txt ~/dmesg.txt
```

Then shut down with `sudo poweroff` and wait until the console is fully off.
The boot report hides Wi-Fi names and MAC addresses but keeps IP addresses.

## What the result means

| What you see | What to send |
|---|---|
| A refusal message on screen | A photo of it and `loader-output.txt` |
| A kernel panic before Rest Mode | `loader-output.txt`, the last lines matter most |
| Solid orange, then blue pulsing or it powers off | The light timeline and `loader-output.txt` |
| White light but no SSH after three minutes | Wait five more minutes, then report that |
| SSH works | The files from step 4 |
