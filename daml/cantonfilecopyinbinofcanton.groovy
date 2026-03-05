canton {

  parameters {
    non-standard-config = yes
  }

  features {
    enable-testing-commands = yes
  }

  participants {
    local {
      storage.type = memory

      admin-api {
        address = "127.0.0.1"
        port    = 6865
      }

      ledger-api {
        address = "127.0.0.1"
        port    = 6866
      }
    }
  }

  domains {
    myLocalDomain {
      init {
        domain-parameters {
          protocol-version = 7
        }
      }

      storage.type = memory

      admin-api {
        address = "127.0.0.1"
        port    = 7500
      }

      public-api {
        address = "127.0.0.1"
        port    = 7575
      }
    }
  }

  # Optional bootstrap script:
  # bootstrap = "bootstrap.canton"
}
