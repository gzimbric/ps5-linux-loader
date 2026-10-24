# PS5 Pro 11.60 Linux test 3

This is an experimental Linux test for a retail PS5 Pro on firmware 11.60
(`0x11600005`). Test 3 is the first Pro build with a picture. On one Pro it
booted to the Ubuntu desktop at 1080p over HDMI, twice from a cold boot.

Test 1 panicked on every Pro. Test 2 booted Linux but the TV showed no signal,
because it skipped the display setup on the Pro. Test 3 runs the same display
setup as a regular PS5. Don't use test 1, test 2, the Run 18 or Run 21 loaders,
or any other loader on a Pro.

## Downloads

- [ps5-linux-loader-1160-dma-e820-bounded.elf](https://github.com/gzimbric/ps5-linux-loader/releases/download/firmware-11.60-pro-linux-test-3/ps5-linux-loader-1160-dma-e820-bounded.elf)
- [Ubuntu Image 3](https://github.com/gzimbric/ps5-linux-image/releases/download/ubuntu2404-k73-image-3/ps5-ubuntu2404-k73.img.xz)

```text
3ab6609fb36edec23d3964215690563cb92071a0831f00608d977d9d7be7ce0b  ps5-linux-loader-1160-dma-e820-bounded.elf
9f038b316be5595b5b1629a86470cd7b955cf977741e022d9e1135898746de04  ps5-ubuntu2404-k73.img.xz
```

Check a file with `shasum -a 256 FILE` on Mac or Linux, or
`Get-FileHash FILE -Algorithm SHA256` in PowerShell on Windows.

## 1. Flash the USB drive

Flash `ps5-ubuntu2404-k73.img.xz` with balenaEtcher or Raspberry Pi Imager and
let it finish the verify step. If your computer offers to format the drive
afterwards, say no. If you already flashed Image 3 for test 2, keep the drive
and only change `cmdline.txt` below.

## 2. Edit cmdline.txt

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

If you added the test 2 line, remove it. Then add this to the end of the
existing line, with one space before it. Keep everything on one line.

```text
modprobe.blacklist=ps5_gpufreq,ps5_cpufreq module_blacklist=ps5_gpufreq,ps5_cpufreq usbcore.autosuspend=-1
```

`usbcore.autosuspend=-1` keeps the Pro's USB ports working. Without it, some
ports stop responding after a few minutes. Don't add `nokaslr`, `mem=` or
`memmap=`. Save, then eject the drive.

## 3. Run the loader

1. Fully power off the PS5 Pro. Don't start from Rest Mode.
2. Plug in the USB drive and an Ethernet cable, then power on.
3. Run your jailbreak and elfldr only. No etaHEN, kstuff or other payloads.
4. Send the ELF once, in a way that shows its output, and save that output.
   On Mac or Linux, install `socat` and run this.

   ```bash
   socat -t 9999999 - TCP:PS5_IP:9021 < ps5-linux-loader-1160-dma-e820-bounded.elf | tee loader-output.txt
   ```

   On Windows, put the ELF on your desktop and run this in PowerShell, with
   your PS5's address in place of `PS5_IP`.

   ```text
   $c=New-Object Net.Sockets.TcpClient('PS5_IP',9021); $s=$c.GetStream(); $s.ReadTimeout=60000; $b=[IO.File]::ReadAllBytes("$HOME\Desktop\ps5-linux-loader-1160-dma-e820-bounded.elf"); $s.Write($b,0,$b.Length); $c.Client.Shutdown('Send'); $r=New-Object IO.StreamReader($s); try { while(($l=$r.ReadLine()) -ne $null){ $l; Add-Content "$HOME\loader-output.txt" $l } } catch {}; $c.Close()
   ```

   Payload sender apps cut off the end of the output, so avoid them if you can.
5. The loader puts the console into Rest Mode by itself. Wait for a solid
   orange light, then press the power button once.
6. The light turns white, the TV shows boot messages, then the Ubuntu desktop.
   SSH also works over Ethernet with `ssh ps5@CONSOLE_IP` and the password
   `ubuntu`.

Never send the loader twice in the same boot. If anything goes wrong, fully
power off before trying again.

## Known issues

- Bluetooth doesn't work on the Pro yet. Use a wired controller, mouse and
  keyboard.
- The GPU runs at its default clock. The PS5 clock boost is off on the Pro and
  Linux can't read the GPU temperature yet, so stick to light use for now.
  Games are untested.
- The Linux drive ran at USB 2 speed in the port we tested, so installs and
  loading are slow.
- Linux shows about 15 GB of memory. That's normal: part goes to the GPU and
  the extra 2 GB on the Pro is used by the console itself.
- `ps5-boot-report.service` fails on this image. It doesn't affect anything
  else.

## 4. Send back the results

Send these privately, not in a public channel.

- `loader-output.txt` or photos of the on-screen messages
- What the light and the TV did after you pressed the power button
- Your console model (the CFI number on the back)

If SSH works, also run this and send the two files.

```bash
sudo journalctl -b --no-pager > ~/journal.txt
sudo dmesg > ~/dmesg.txt
```

Then shut down with `sudo poweroff` and wait until the console is fully off.

## What the result means

| What you see | What to send |
|---|---|
| A refusal message on screen | A photo of it and `loader-output.txt` |
| A kernel panic before Rest Mode | `loader-output.txt`, the last lines matter most |
| Solid orange, then blue pulsing or it powers off | The light timeline and `loader-output.txt` |
| White light but the TV says no signal | Check SSH, then send the files from step 4 |
| The desktop shows up | The files from step 4 and anything that doesn't work |
