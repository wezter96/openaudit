resource "azurerm_linux_virtual_machine" "vm" {
  name                  = "vm"
  resource_group_name   = "rg"
  location              = "westeurope"
  size                  = "Standard_Z99"
  admin_username        = "azureuser"
  network_interface_ids = []

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server"
    version   = "latest"
  }
}
