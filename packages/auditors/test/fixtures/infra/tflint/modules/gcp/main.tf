resource "google_compute_instance" "vm" {
  name         = "vm"
  machine_type = "n9-standard-1"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }

  network_interface {
    network = "default"
  }
}
