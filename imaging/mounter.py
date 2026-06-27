# imaging/mounter.py
import os
import subprocess
from loguru import logger


def mount_img(image_path: str, mount_dir: str) -> str | None:
    """
    Mount a disk image file read-only via a loop device.

    Tries the first partition (<loop>p1) first; falls back to the raw loop
    device if no partition is found.

    Args:
        image_path: Path to the .img file.
        mount_dir:  Directory to mount the image at.

    Returns:
        The mount directory path on success, None on failure.
    """
    try:
        # Detach any existing loop devices attached to this image
        result = subprocess.run(
            ["losetup", "-j", image_path],
            capture_output=True, text=True, check=True,
        )
        for line in result.stdout.strip().splitlines():
            loop_dev = line.split(":")[0]
            subprocess.run(["sudo", "losetup", "-d", loop_dev], check=True)
            logger.debug(f"Detached existing loop device: {loop_dev}")

        # Attach with partition scanning
        subprocess.run(["sudo", "losetup", "-Pf", image_path], check=True)
        logger.debug(f"Attached loop device for image: {image_path}")

        # Resolve the new loop device name
        result = subprocess.run(
            ["losetup", "-j", image_path],
            capture_output=True, text=True, check=True,
        )
        loop_dev = result.stdout.split(":")[0].strip()

        # Prefer the first partition; fall back to the raw loop device
        part_dev = f"{loop_dev}p1"
        device_to_mount = part_dev if os.path.exists(part_dev) else loop_dev

        if not os.path.exists(device_to_mount):
            logger.error(
                f"Neither partition device '{part_dev}' nor loop device "
                f"'{loop_dev}' exists."
            )
            return None

        os.makedirs(mount_dir, exist_ok=True)
        subprocess.run(
            ["sudo", "mount", "-o", "ro", device_to_mount, mount_dir],
            check=True,
        )
        logger.info(f"Mounted '{device_to_mount}' at '{mount_dir}'")
        return mount_dir

    except subprocess.CalledProcessError as e:
        logger.error(f"Mount command failed: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error during mount: {e}")
        return None


def unmount_img(mount_dir: str, image_path: str) -> bool:
    """
    Unmount a mounted directory and detach the associated loop device(s).

    Args:
        mount_dir:  The directory to unmount.
        image_path: The image file used to find associated loop devices.

    Returns:
        True on success, False on failure.
    """
    try:
        if os.path.ismount(mount_dir):
            subprocess.run(["sudo", "umount", mount_dir], check=True)
            logger.info(f"Unmounted '{mount_dir}'")
        else:
            logger.warning(f"'{mount_dir}' is not currently mounted — skipping umount.")

        # Detach all loop devices associated with the image
        result = subprocess.run(
            ["losetup", "-j", image_path],
            capture_output=True, text=True, check=True,
        )
        loop_devs = [
            line.split(":")[0]
            for line in result.stdout.strip().splitlines()
            if line
        ]

        for dev in loop_devs:
            subprocess.run(["sudo", "losetup", "-d", dev], check=True)
            logger.info(f"Detached loop device '{dev}'")

        return True

    except subprocess.CalledProcessError as e:
        logger.error(f"Unmount command failed: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during unmount: {e}")
        return False
