// pkg/services/vault_blockchain_listener.go
package services

import (
	"Raze-untapped-backend/pkg/models"
	"Raze-untapped-backend/pkg/repository"
	"Raze-untapped-backend/pkg/utils"
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"math/big"
	"strings"
	"sync"
	"time"

	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretspb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
)

// UPDATED: Complete Vault contract ABI with single status system events (for Ferrox vaults)
const vaultContractABI = `
[
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "address", "name": "user", "type": "address"},
      {"indexed": true, "internalType": "uint256", "name": "positionId", "type": "uint256"},
      {"indexed": false, "internalType": "uint8", "name": "tier", "type": "uint8"},
      {"indexed": false, "internalType": "uint256", "name": "originalAmount", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "principalAmount", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "taxAmount", "type": "uint256"},
      {"indexed": false, "internalType": "bool", "name": "rolloverEnabled", "type": "bool"},
      {"indexed": false, "internalType": "uint256", "name": "lockEndTime", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "depositTime", "type": "uint256"},
      {"indexed": false, "internalType": "string", "name": "vaultName", "type": "string"},
      {"indexed": false, "internalType": "string", "name": "vaultSymbol", "type": "string"},
      {"indexed": false, "internalType": "uint256", "name": "arrRate", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "lockPeriodDays", "type": "uint256"}
    ],
    "name": "VaultDeposit",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "address", "name": "user", "type": "address"},
      {"indexed": true, "internalType": "uint256", "name": "positionId", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "principalAmount", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "rewardsAmount", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "totalAmount", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "redemptionTax", "type": "uint256"},
      {"indexed": false, "internalType": "uint8", "name": "tier", "type": "uint8"},
      {"indexed": false, "internalType": "string", "name": "vaultName", "type": "string"},
      {"indexed": false, "internalType": "string", "name": "vaultSymbol", "type": "string"},
      {"indexed": false, "internalType": "uint256", "name": "depositTime", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "lockEndTime", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "redeemTime", "type": "uint256"}
    ],
    "name": "VaultRedeemed",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "address", "name": "user", "type": "address"},
      {"indexed": true, "internalType": "uint256", "name": "positionId", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "availableTime", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "requestTime", "type": "uint256"},
      {"indexed": false, "internalType": "uint8", "name": "tier", "type": "uint8"},
      {"indexed": false, "internalType": "uint256", "name": "originalAmount", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "currentValue", "type": "uint256"}
    ],
    "name": "RedemptionRequested",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "address", "name": "user", "type": "address"},
      {"indexed": true, "internalType": "uint256", "name": "positionId", "type": "uint256"},
      {"indexed": false, "internalType": "uint8", "name": "oldStatus", "type": "uint8"},
      {"indexed": false, "internalType": "uint8", "name": "newStatus", "type": "uint8"},
      {"indexed": false, "internalType": "uint256", "name": "updateTime", "type": "uint256"}
    ],
    "name": "PositionStatusUpdated",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "address", "name": "user", "type": "address"},
      {"indexed": true, "internalType": "uint256", "name": "positionId", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "newLockEndTime", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "rolloverTime", "type": "uint256"},
      {"indexed": false, "internalType": "uint8", "name": "tier", "type": "uint8"}
    ],
    "name": "VaultRolledOver",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "address", "name": "admin", "type": "address"},
      {"indexed": false, "internalType": "uint256", "name": "timestamp", "type": "uint256"}
    ],
    "name": "ContractPaused",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "address", "name": "admin", "type": "address"},
      {"indexed": false, "internalType": "uint256", "name": "timestamp", "type": "uint256"}
    ],
    "name": "ContractUnpaused",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "address", "name": "from", "type": "address"},
      {"indexed": true, "internalType": "address", "name": "to", "type": "address"},
      {"indexed": true, "internalType": "uint256", "name": "positionId", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "amount", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "timestamp", "type": "uint256"}
    ],
    "name": "XTFTokensTransferred",
    "type": "event"
  }
]
`

// Compute Labs Vault contract ABI (different event structure from Ferrox)
const computeLabsVaultABI = `
[
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "address", "name": "user", "type": "address"},
      {"indexed": true, "internalType": "uint256", "name": "positionId", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "originalAmount", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "principalAmount", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "taxAmount", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "lockEndTime", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "depositTime", "type": "uint256"},
      {"indexed": false, "internalType": "string", "name": "vaultName", "type": "string"},
      {"indexed": false, "internalType": "string", "name": "vaultSymbol", "type": "string"},
      {"indexed": false, "internalType": "uint256", "name": "apyRate", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "lockPeriodDays", "type": "uint256"}
    ],
    "name": "VaultDeposit",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "address", "name": "user", "type": "address"},
      {"indexed": true, "internalType": "uint256", "name": "positionId", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "principalAmount", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "yieldAmount", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "totalAmount", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "redemptionTax", "type": "uint256"},
      {"indexed": false, "internalType": "string", "name": "vaultName", "type": "string"},
      {"indexed": false, "internalType": "string", "name": "vaultSymbol", "type": "string"},
      {"indexed": false, "internalType": "uint256", "name": "depositTime", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "redeemTime", "type": "uint256"}
    ],
    "name": "VaultRedeemed",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "address", "name": "user", "type": "address"},
      {"indexed": true, "internalType": "uint256", "name": "positionId", "type": "uint256"},
      {"indexed": false, "internalType": "uint8", "name": "oldStatus", "type": "uint8"},
      {"indexed": false, "internalType": "uint8", "name": "newStatus", "type": "uint8"},
      {"indexed": false, "internalType": "uint256", "name": "updateTime", "type": "uint256"}
    ],
    "name": "PositionStatusUpdated",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "address", "name": "admin", "type": "address"},
      {"indexed": false, "internalType": "uint256", "name": "timestamp", "type": "uint256"}
    ],
    "name": "ContractPaused",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "address", "name": "admin", "type": "address"},
      {"indexed": false, "internalType": "uint256", "name": "timestamp", "type": "uint256"}
    ],
    "name": "ContractUnpaused",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "address", "name": "from", "type": "address"},
      {"indexed": true, "internalType": "address", "name": "to", "type": "address"},
      {"indexed": true, "internalType": "uint256", "name": "positionId", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "amount", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "timestamp", "type": "uint256"}
    ],
    "name": "CLGPUTokensTransferred",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "address", "name": "user", "type": "address"},
      {"indexed": true, "internalType": "uint256", "name": "positionId", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "yieldAmount", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "taxAmount", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "claimTime", "type": "uint256"}
    ],
    "name": "DistributionClaimed",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "address", "name": "admin", "type": "address"},
      {"indexed": false, "internalType": "uint256", "name": "firstDistributionDate", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "timestamp", "type": "uint256"}
    ],
    "name": "DistributionScheduleInitiated",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "address", "name": "admin", "type": "address"},
      {"indexed": false, "internalType": "uint256", "name": "buyoutDate", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "timestamp", "type": "uint256"}
    ],
    "name": "BuyoutScheduled",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "address", "name": "admin", "type": "address"},
      {"indexed": false, "internalType": "uint256", "name": "totalPositionsAffected", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "timestamp", "type": "uint256"}
    ],
    "name": "BuyoutExecuted",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "address", "name": "admin", "type": "address"},
      {"indexed": false, "internalType": "uint256", "name": "timestamp", "type": "uint256"}
    ],
    "name": "VaultClosedToNewInvestments",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "address", "name": "admin", "type": "address"},
      {"indexed": false, "internalType": "uint256", "name": "timestamp", "type": "uint256"}
    ],
    "name": "VaultReopened",
    "type": "event"
  }
]
`

// 129Knots vault contract ABI (KnotsFinanceVault - contracts/129Vault.sol)
const knotsVaultABI = `
[
  {
    "inputs": [
      {"internalType": "address", "name": "initialOwner", "type": "address"},
      {"internalType": "address", "name": "_usdcAddress", "type": "address"},
      {"internalType": "address", "name": "_noteTokenAddress", "type": "address"},
      {"internalType": "address", "name": "_taxAddress", "type": "address"},
      {"internalType": "address", "name": "_treasuryWallet", "type": "address"},
      {"internalType": "address", "name": "_ratePublisherAddress", "type": "address"}
    ],
    "stateMutability": "nonpayable",
    "type": "constructor"
  },
  {
    "inputs": [{"internalType": "address", "name": "owner", "type": "address"}],
    "name": "OwnableInvalidOwner",
    "type": "error"
  },
  {
    "inputs": [{"internalType": "address", "name": "account", "type": "address"}],
    "name": "OwnableUnauthorizedAccount",
    "type": "error"
  },
  {"inputs": [], "name": "ReentrancyGuardReentrantCall", "type": "error"},
  {
    "inputs": [{"internalType": "address", "name": "token", "type": "address"}],
    "name": "SafeERC20FailedOperation",
    "type": "error"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "address", "name": "admin", "type": "address"},
      {"indexed": false, "internalType": "uint256", "name": "timestamp", "type": "uint256"}
    ],
    "name": "ContractPaused",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "address", "name": "admin", "type": "address"},
      {"indexed": false, "internalType": "uint256", "name": "timestamp", "type": "uint256"}
    ],
    "name": "ContractUnpaused",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": false, "internalType": "uint256", "name": "tranche", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "oldRate", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "newRate", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "timestamp", "type": "uint256"}
    ],
    "name": "DepositTaxRateUpdated",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "address", "name": "oldRegistry", "type": "address"},
      {"indexed": true, "internalType": "address", "name": "newRegistry", "type": "address"},
      {"indexed": false, "internalType": "uint256", "name": "timestamp", "type": "uint256"}
    ],
    "name": "IdentityRegistryUpdated",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "address", "name": "to", "type": "address"},
      {"indexed": true, "internalType": "uint256", "name": "positionId", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "amount", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "timestamp", "type": "uint256"}
    ],
    "name": "NoteTokensMinted",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "address", "name": "previousOwner", "type": "address"},
      {"indexed": true, "internalType": "address", "name": "newOwner", "type": "address"}
    ],
    "name": "OwnershipTransferred",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "address", "name": "user", "type": "address"},
      {"indexed": true, "internalType": "uint256", "name": "positionId", "type": "uint256"},
      {"indexed": false, "internalType": "uint8", "name": "oldStatus", "type": "uint8"},
      {"indexed": false, "internalType": "uint8", "name": "newStatus", "type": "uint8"},
      {"indexed": false, "internalType": "uint256", "name": "updateTime", "type": "uint256"}
    ],
    "name": "PositionStatusUpdated",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "address", "name": "oldAddress", "type": "address"},
      {"indexed": true, "internalType": "address", "name": "newAddress", "type": "address"},
      {"indexed": false, "internalType": "uint256", "name": "timestamp", "type": "uint256"}
    ],
    "name": "RatePublisherUpdated",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "address", "name": "user", "type": "address"},
      {"indexed": true, "internalType": "uint256", "name": "positionId", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "availableTime", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "requestTime", "type": "uint256"},
      {"indexed": false, "internalType": "uint8", "name": "tier", "type": "uint8"},
      {"indexed": false, "internalType": "uint256", "name": "originalAmount", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "currentValue", "type": "uint256"}
    ],
    "name": "RedemptionRequested",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": false, "internalType": "uint256", "name": "oldRate", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "newRate", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "timestamp", "type": "uint256"}
    ],
    "name": "SOFRRateUpdated",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": false, "internalType": "bool", "name": "enabled", "type": "bool"},
      {"indexed": false, "internalType": "uint256", "name": "timestamp", "type": "uint256"}
    ],
    "name": "TVLCheckToggled",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": false, "internalType": "uint256", "name": "oldLimit", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "newLimit", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "timestamp", "type": "uint256"}
    ],
    "name": "TVLLimitUpdated",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": false, "internalType": "uint256", "name": "oldTVL", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "newTVL", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "timestamp", "type": "uint256"}
    ],
    "name": "TVLUpdated",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "address", "name": "oldAddress", "type": "address"},
      {"indexed": true, "internalType": "address", "name": "newAddress", "type": "address"},
      {"indexed": false, "internalType": "uint256", "name": "timestamp", "type": "uint256"}
    ],
    "name": "TaxAddressUpdated",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "address", "name": "oldAddress", "type": "address"},
      {"indexed": true, "internalType": "address", "name": "newAddress", "type": "address"},
      {"indexed": false, "internalType": "uint256", "name": "timestamp", "type": "uint256"}
    ],
    "name": "TreasuryWalletUpdated",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "address", "name": "user", "type": "address"},
      {"indexed": true, "internalType": "uint256", "name": "positionId", "type": "uint256"},
      {"indexed": false, "internalType": "uint8", "name": "tier", "type": "uint8"},
      {"indexed": false, "internalType": "uint256", "name": "originalAmount", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "principalAmount", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "taxAmount", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "lockEndTime", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "depositTime", "type": "uint256"},
      {"indexed": false, "internalType": "string", "name": "vaultName", "type": "string"},
      {"indexed": false, "internalType": "string", "name": "vaultSymbol", "type": "string"},
      {"indexed": false, "internalType": "uint256", "name": "arrRate", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "lockPeriodDays", "type": "uint256"}
    ],
    "name": "VaultDeposit",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "address", "name": "user", "type": "address"},
      {"indexed": true, "internalType": "uint256", "name": "positionId", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "principalAmount", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "rewardsAmount", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "totalAmount", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "redemptionTax", "type": "uint256"},
      {"indexed": false, "internalType": "uint8", "name": "tier", "type": "uint8"},
      {"indexed": false, "internalType": "string", "name": "vaultName", "type": "string"},
      {"indexed": false, "internalType": "string", "name": "vaultSymbol", "type": "string"},
      {"indexed": false, "internalType": "uint256", "name": "depositTime", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "lockEndTime", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "redeemTime", "type": "uint256"}
    ],
    "name": "VaultRedeemed",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "address", "name": "user", "type": "address"},
      {"indexed": true, "internalType": "uint256", "name": "positionId", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "newLockEndTime", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "rolloverTime", "type": "uint256"},
      {"indexed": false, "internalType": "uint8", "name": "tier", "type": "uint8"}
    ],
    "name": "VaultRolledOver",
    "type": "event"
  },
  {
    "inputs": [],
    "name": "BPS_DENOMINATOR",
    "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "SCALE",
    "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "SECONDS_PER_DAY",
    "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "SECONDS_PER_YEAR",
    "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {"internalType": "address", "name": "_user", "type": "address"},
      {"internalType": "uint256", "name": "_positionId", "type": "uint256"}
    ],
    "name": "calculateDisplayRewards",
    "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {"internalType": "address", "name": "_user", "type": "address"},
      {"internalType": "uint256", "name": "_positionId", "type": "uint256"}
    ],
    "name": "canRedeem",
    "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "contractPaused",
    "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "currentSOFRRate",
    "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "currentTVL",
    "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {"internalType": "uint256", "name": "_amount", "type": "uint256"},
      {"internalType": "enum KnotsFinanceVault.Tranche", "name": "_tranche", "type": "uint8"}
    ],
    "name": "depositToVault",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [{"internalType": "uint256", "name": "_amount", "type": "uint256"}],
    "name": "fundContractWithUsdc",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "getActualTVL",
    "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "getAvailableDepositCapacity",
    "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "getContractStats",
    "outputs": [
      {"internalType": "uint256", "name": "totalPositions", "type": "uint256"},
      {"internalType": "uint256", "name": "totalFees", "type": "uint256"},
      {"internalType": "uint256", "name": "totalRedemptions", "type": "uint256"},
      {"internalType": "bool", "name": "isPaused", "type": "bool"}
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {"internalType": "address", "name": "_user", "type": "address"},
      {"internalType": "uint256", "name": "_positionId", "type": "uint256"}
    ],
    "name": "getCurrentPositionStatus",
    "outputs": [{"internalType": "uint8", "name": "", "type": "uint8"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "getCurrentSOFR",
    "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [{"internalType": "enum KnotsFinanceVault.Tranche", "name": "_tranche", "type": "uint8"}],
    "name": "getDepositTaxRate",
    "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [{"internalType": "enum KnotsFinanceVault.Tranche", "name": "_tranche", "type": "uint8"}],
    "name": "getEstimatedAPY",
    "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "getIdentityRegistry",
    "outputs": [{"internalType": "address", "name": "", "type": "address"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {"internalType": "address", "name": "_user", "type": "address"},
      {"internalType": "uint256", "name": "_positionId", "type": "uint256"}
    ],
    "name": "getPositionLockEndTime",
    "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {"internalType": "address", "name": "_user", "type": "address"},
      {"internalType": "uint256", "name": "_positionId", "type": "uint256"}
    ],
    "name": "getPositionLockedRate",
    "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "getTVLInfo",
    "outputs": [
      {"internalType": "uint256", "name": "current", "type": "uint256"},
      {"internalType": "uint256", "name": "maximum", "type": "uint256"},
      {"internalType": "uint256", "name": "available", "type": "uint256"},
      {"internalType": "uint256", "name": "utilizationBasisPoints", "type": "uint256"},
      {"internalType": "bool", "name": "checkEnabled", "type": "bool"}
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "getTVLUtilization",
    "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "getTrackedUserCount",
    "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [{"internalType": "enum KnotsFinanceVault.Tranche", "name": "_tranche", "type": "uint8"}],
    "name": "getTrancheConfig",
    "outputs": [
      {
        "components": [
          {"internalType": "uint256", "name": "termDays", "type": "uint256"},
          {"internalType": "uint256", "name": "netSpreadBps", "type": "uint256"},
          {"internalType": "uint256", "name": "grossSpreadBps", "type": "uint256"},
          {"internalType": "uint256", "name": "minInvestment", "type": "uint256"},
          {"internalType": "uint256", "name": "platformFeeBps", "type": "uint256"},
          {"internalType": "bool", "name": "isActive", "type": "bool"},
          {"internalType": "string", "name": "name", "type": "string"},
          {"internalType": "string", "name": "symbol", "type": "string"}
        ],
        "internalType": "struct KnotsFinanceVault.TrancheConfig",
        "name": "",
        "type": "tuple"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {"internalType": "address", "name": "_user", "type": "address"},
      {"internalType": "uint256", "name": "_positionId", "type": "uint256"}
    ],
    "name": "getUserPosition",
    "outputs": [
      {
        "components": [
          {"internalType": "uint256", "name": "originalInvestmentAmount", "type": "uint256"},
          {"internalType": "uint256", "name": "principalAmount", "type": "uint256"},
          {"internalType": "uint256", "name": "depositTime", "type": "uint256"},
          {"internalType": "enum KnotsFinanceVault.Tranche", "name": "tranche", "type": "uint8"},
          {"internalType": "enum KnotsFinanceVault.PositionStatus", "name": "status", "type": "uint8"},
          {"internalType": "uint256", "name": "lockedRateBps", "type": "uint256"},
          {"internalType": "uint256", "name": "lockedGrossRateBps", "type": "uint256"},
          {"internalType": "uint256", "name": "lockEndTime", "type": "uint256"},
          {"internalType": "uint256", "name": "redemptionRequestTime", "type": "uint256"},
          {"internalType": "uint256", "name": "lastRewardClaim", "type": "uint256"},
          {"internalType": "uint256", "name": "totalRewardsClaimed", "type": "uint256"}
        ],
        "internalType": "struct KnotsFinanceVault.VaultPosition",
        "name": "",
        "type": "tuple"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [{"internalType": "address", "name": "_user", "type": "address"}],
    "name": "getUserPositionCount",
    "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "globalRedemptionCount",
    "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "identityRegistry",
    "outputs": [{"internalType": "contract IIdentityRegistry", "name": "", "type": "address"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {"internalType": "address", "name": "_user", "type": "address"},
      {"internalType": "uint256", "name": "_positionId", "type": "uint256"}
    ],
    "name": "isPositionCompleted",
    "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [{"internalType": "address", "name": "", "type": "address"}],
    "name": "isTrackedUser",
    "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [{"internalType": "address", "name": "_user", "type": "address"}],
    "name": "isUserKYCVerified",
    "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "lastSOFRUpdate",
    "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "maxTVL",
    "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "noteToken",
    "outputs": [{"internalType": "contract IERC20Mintable", "name": "", "type": "address"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "owner",
    "outputs": [{"internalType": "address", "name": "", "type": "address"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "pauseContract",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "ratePublisher",
    "outputs": [{"internalType": "contract IRatePublisher", "name": "", "type": "address"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [{"internalType": "uint256", "name": "_positionId", "type": "uint256"}],
    "name": "redeemPosition",
    "outputs": [
      {"internalType": "uint256", "name": "principalAmount", "type": "uint256"},
      {"internalType": "uint256", "name": "interestAmount", "type": "uint256"},
      {"internalType": "uint256", "name": "totalAmount", "type": "uint256"}
    ],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "refreshSOFRRate",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "renounceOwnership",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [{"internalType": "uint256", "name": "_positionId", "type": "uint256"}],
    "name": "requestRedemption",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [
      {"internalType": "enum KnotsFinanceVault.Tranche", "name": "_tranche", "type": "uint8"},
      {"internalType": "uint256", "name": "_newRate", "type": "uint256"}
    ],
    "name": "setDepositTaxRate",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [{"internalType": "address", "name": "_newIdentityRegistry", "type": "address"}],
    "name": "setIdentityRegistry",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [{"internalType": "address", "name": "_newRatePublisher", "type": "address"}],
    "name": "setRatePublisher",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [{"internalType": "bool", "name": "_enabled", "type": "bool"}],
    "name": "setTVLCheckEnabled",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [{"internalType": "uint256", "name": "_newLimit", "type": "uint256"}],
    "name": "setTVLLimit",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "taxAddress",
    "outputs": [{"internalType": "address", "name": "", "type": "address"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "totalFeesCollected",
    "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "totalPositionsCreated",
    "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
    "name": "trackedUsers",
    "outputs": [{"internalType": "address", "name": "", "type": "address"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [{"internalType": "enum KnotsFinanceVault.Tranche", "name": "", "type": "uint8"}],
    "name": "trancheConfigs",
    "outputs": [
      {"internalType": "uint256", "name": "termDays", "type": "uint256"},
      {"internalType": "uint256", "name": "netSpreadBps", "type": "uint256"},
      {"internalType": "uint256", "name": "grossSpreadBps", "type": "uint256"},
      {"internalType": "uint256", "name": "minInvestment", "type": "uint256"},
      {"internalType": "uint256", "name": "platformFeeBps", "type": "uint256"},
      {"internalType": "bool", "name": "isActive", "type": "bool"},
      {"internalType": "string", "name": "name", "type": "string"},
      {"internalType": "string", "name": "symbol", "type": "string"}
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [{"internalType": "address", "name": "newOwner", "type": "address"}],
    "name": "transferOwnership",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "treasuryWallet",
    "outputs": [{"internalType": "address", "name": "", "type": "address"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "tvlCheckEnabled",
    "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "unpauseContract",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [{"internalType": "address", "name": "_newTaxAddress", "type": "address"}],
    "name": "updateTaxAddress",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [{"internalType": "address", "name": "_newTreasuryWallet", "type": "address"}],
    "name": "updateTreasuryWallet",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "usdcToken",
    "outputs": [{"internalType": "contract IERC20", "name": "", "type": "address"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {"internalType": "address", "name": "", "type": "address"},
      {"internalType": "uint256", "name": "", "type": "uint256"}
    ],
    "name": "userPositions",
    "outputs": [
      {"internalType": "uint256", "name": "originalInvestmentAmount", "type": "uint256"},
      {"internalType": "uint256", "name": "principalAmount", "type": "uint256"},
      {"internalType": "uint256", "name": "depositTime", "type": "uint256"},
      {"internalType": "enum KnotsFinanceVault.Tranche", "name": "tranche", "type": "uint8"},
      {"internalType": "enum KnotsFinanceVault.PositionStatus", "name": "status", "type": "uint8"},
      {"internalType": "uint256", "name": "lockedRateBps", "type": "uint256"},
      {"internalType": "uint256", "name": "lockedGrossRateBps", "type": "uint256"},
      {"internalType": "uint256", "name": "lockEndTime", "type": "uint256"},
      {"internalType": "uint256", "name": "redemptionRequestTime", "type": "uint256"},
      {"internalType": "uint256", "name": "lastRewardClaim", "type": "uint256"},
      {"internalType": "uint256", "name": "totalRewardsClaimed", "type": "uint256"}
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [{"internalType": "uint256", "name": "_amount", "type": "uint256"}],
    "name": "willDepositExceedTVL",
    "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
    "stateMutability": "view",
    "type": "function"
  }
]
`

// Raze Reserve vault contract ABI (different event structure from Ferrox)
const razeReserveVaultABI = `
[
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "address", "name": "user", "type": "address"},
      {"indexed": true, "internalType": "uint256", "name": "positionId", "type": "uint256"},
      {"indexed": false, "internalType": "uint8", "name": "tier", "type": "uint8"},
      {"indexed": false, "internalType": "uint256", "name": "originalAmount", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "lockEndTime", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "depositTime", "type": "uint256"},
      {"indexed": false, "internalType": "string", "name": "tierName", "type": "string"},
      {"indexed": false, "internalType": "string", "name": "tierSymbol", "type": "string"},
      {"indexed": false, "internalType": "uint256", "name": "lockedApyBps", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "lockPeriodDays", "type": "uint256"},
      {"indexed": false, "internalType": "bool", "name": "rolloverEnabled", "type": "bool"},
      {"indexed": false, "internalType": "uint256", "name": "taxAmount", "type": "uint256"}
    ],
    "name": "VaultDeposit",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "address", "name": "user", "type": "address"},
      {"indexed": true, "internalType": "uint256", "name": "positionId", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "availableTime", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "requestTime", "type": "uint256"},
      {"indexed": false, "internalType": "uint8", "name": "tier", "type": "uint8"},
      {"indexed": false, "internalType": "uint256", "name": "originalAmount", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "currentValue", "type": "uint256"}
    ],
    "name": "RedemptionRequested",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "address", "name": "user", "type": "address"},
      {"indexed": true, "internalType": "uint256", "name": "positionId", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "newLockEndTime", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "rolloverTime", "type": "uint256"},
      {"indexed": false, "internalType": "uint8", "name": "tier", "type": "uint8"}
    ],
    "name": "VaultRolledOver",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "address", "name": "user", "type": "address"},
      {"indexed": true, "internalType": "uint256", "name": "positionId", "type": "uint256"},
      {"indexed": false, "internalType": "uint8", "name": "oldStatus", "type": "uint8"},
      {"indexed": false, "internalType": "uint8", "name": "newStatus", "type": "uint8"},
      {"indexed": false, "internalType": "uint256", "name": "updateTime", "type": "uint256"}
    ],
    "name": "PositionStatusUpdated",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "address", "name": "to", "type": "address"},
      {"indexed": true, "internalType": "uint256", "name": "positionId", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "amount", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "timestamp", "type": "uint256"}
    ],
    "name": "NoteTokensMinted",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "address", "name": "user", "type": "address"},
      {"indexed": true, "internalType": "uint256", "name": "positionId", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "principalAmount", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "pendingReward", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "totalAmount", "type": "uint256"},
      {"indexed": false, "internalType": "uint8", "name": "tier", "type": "uint8"},
      {"indexed": false, "internalType": "string", "name": "tierName", "type": "string"},
      {"indexed": false, "internalType": "string", "name": "tierSymbol", "type": "string"},
      {"indexed": false, "internalType": "uint256", "name": "depositTime", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "lockEndTime", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "redeemTime", "type": "uint256"},
      {"indexed": false, "internalType": "uint256", "name": "redemptionTax", "type": "uint256"}
    ],
    "name": "VaultRedeemed",
    "type": "event"
  }
]
`

// FeTi70 Token contract ABI (unchanged)
const feti70ContractABI = `
[
  {
    "inputs": [
      {"internalType": "address", "name": "to", "type": "address"},
      {"internalType": "uint256", "name": "amount", "type": "uint256"}
    ],
    "name": "transfer",
    "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "decimals",
    "outputs": [{"internalType": "uint8", "name": "", "type": "uint8"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [{"internalType": "address", "name": "account", "type": "address"}],
    "name": "balanceOf",
    "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
    "stateMutability": "view",
    "type": "function"
  }
]
`

// RedbellyConfig holds Redbelly network configuration
type RedbellyConfig struct {
	RPCUrl             string
	FeTi70ContractAddr common.Address
	PrivateKey         *ecdsa.PrivateKey
	ChainID            *big.Int
}

// Global instance for manual trigger access
var globalVaultListener *VaultBlockchainListener
var listenerMutex sync.Mutex

// VaultBlockchainListener monitors vault contract events
type VaultBlockchainListener struct {
	clients           map[int64]*ethclient.Client
	stopChannels      map[int64]chan struct{}
	wg                sync.WaitGroup
	contractAddresses map[int64][]common.Address
	vaultService      *VaultService
	// Redbelly network configuration
	redbellyClient *ethclient.Client
	redbellyConfig *RedbellyConfig
	// Error logging service
	errorService *BlockchainErrorService
}

// NewVaultBlockchainListener creates a new vault blockchain listener
func NewVaultBlockchainListener() *VaultBlockchainListener {
	listener := &VaultBlockchainListener{
		clients:           make(map[int64]*ethclient.Client),
		stopChannels:      make(map[int64]chan struct{}),
		contractAddresses: make(map[int64][]common.Address),
		vaultService:      &VaultService{},
		errorService:      &BlockchainErrorService{},
	}

	// Initialize Redbelly configuration
	if err := listener.initializeRedbellyConfig(); err != nil {
		log.Printf("Warning: Failed to initialize Redbelly config: %v", err)
	}

	// Set global instance for manual trigger access
	listenerMutex.Lock()
	globalVaultListener = listener
	listenerMutex.Unlock()

	return listener
}

// GetVaultBlockchainListenerInstance returns the global vault blockchain listener instance
// This is used by the manual trigger API to access the listener for reprocessing events
func GetVaultBlockchainListenerInstance() *VaultBlockchainListener {
	listenerMutex.Lock()
	defer listenerMutex.Unlock()
	return globalVaultListener
}

// initializeRedbellyConfig initializes the Redbelly network configuration
func (s *VaultBlockchainListener) initializeRedbellyConfig() error {
	log.Printf("🔍 [Redbelly Config] Starting Redbelly network configuration...")

	rpcUrl := viper.GetString("redbelly.rpc_url_2")
	contractAddr := viper.GetString("redbelly.feti70_contract_address")
	privateKeyHex := viper.GetString("redbelly.private_key")
	chainID := viper.GetInt64("redbelly.chain_id")

	log.Printf("🔧 [Redbelly Config] Configuration values:")
	log.Printf("🌐 [Redbelly Config] RPC URL: %s", rpcUrl)
	log.Printf("📄 [Redbelly Config] Contract Address: %s", contractAddr)
	log.Printf("🔐 [Redbelly Config] Private Key: %s", func() string {
		if privateKeyHex == "" {
			return "<EMPTY>"
		}
		return "<PROVIDED>"
	}())
	log.Printf("🔗 [Redbelly Config] Chain ID: %d", chainID)

	if rpcUrl == "" {
		log.Printf("❌ [Redbelly Config] RPC URL is missing")
		return fmt.Errorf("missing Redbelly RPC URL configuration")
	}
	if contractAddr == "" {
		log.Printf("❌ [Redbelly Config] Contract address is missing")
		return fmt.Errorf("missing Redbelly contract address configuration")
	}
	// Private key is optional - will be loaded from Secret Manager later if needed
	if privateKeyHex == "" {
		log.Printf("🔑 [Redbelly Config] Private key not in config - will load from Secret Manager when needed")
	}
	log.Printf("✅ [Redbelly Config] All required configuration values are present")

	// Parse private key if providedf
	var privateKey *ecdsa.PrivateKey
	if privateKeyHex != "" {
		log.Printf("🔑 [Redbelly Config] Parsing private key...")
		var err error
		privateKey, err = crypto.HexToECDSA(strings.TrimPrefix(privateKeyHex, "0x"))
		if err != nil {
			log.Printf("❌ [Redbelly Config] Failed to parse private key: %v", err)
			return fmt.Errorf("invalid private key: %v", err)
		}
		log.Printf("✅ [Redbelly Config] Private key parsed successfully")
	} else {
		log.Printf("🔑 [Redbelly Config] Private key will be loaded from Secret Manager when needed")
		privateKey = nil
	}

	// Connect to Redbelly network
	log.Printf("🔌 [Redbelly Config] Connecting to Redbelly network at %s...", rpcUrl)
	client, err := ethclient.Dial(rpcUrl)
	if err != nil {
		log.Printf("❌ [Redbelly Config] Failed to connect to Redbelly network: %v", err)
		return fmt.Errorf("failed to connect to Redbelly network: %v", err)
	}
	log.Printf("✅ [Redbelly Config] Successfully connected to Redbelly network")

	// Verify connection
	log.Printf("🔍 [Redbelly Config] Verifying network connection and chain ID...")
	currentChainID, err := client.ChainID(context.Background())
	if err != nil {
		log.Printf("❌ [Redbelly Config] Failed to get chain ID: %v", err)
		client.Close()
		return fmt.Errorf("failed to get Redbelly chain ID: %v", err)
	}
	log.Printf("🔗 [Redbelly Config] Network chain ID: %d", currentChainID.Int64())

	// Skip chain ID verification if configured chain ID doesn't match
	// This allows using Avalanche Fuji for testing
	if chainID != 0 && currentChainID.Int64() != chainID {
		log.Printf("⚠️ [Redbelly Config] Chain ID mismatch (expected %d, got %d) - proceeding anyway for testing", chainID, currentChainID.Int64())
		// Use the actual chain ID from the network
		chainID = currentChainID.Int64()
	}

	s.redbellyClient = client
	s.redbellyConfig = &RedbellyConfig{
		RPCUrl:             rpcUrl,
		FeTi70ContractAddr: common.HexToAddress(contractAddr),
		PrivateKey:         privateKey,
		ChainID:            big.NewInt(chainID), // Use the corrected chain ID
	}

	log.Printf("✅ [Redbelly Config] Redbelly network configuration completed successfully!")
	log.Printf("🌐 [Redbelly Config] Network: %s", rpcUrl)
	log.Printf("🔗 [Redbelly Config] Chain ID: %d", chainID)
	log.Printf("📄 [Redbelly Config] FeTi70 Contract: %s", contractAddr)
	if privateKey != nil {
		log.Printf("👤 [Redbelly Config] Deployer Address: %s", crypto.PubkeyToAddress(privateKey.PublicKey).Hex())
	} else {
		log.Printf("👤 [Redbelly Config] Deployer Address: Will be determined from Secret Manager")
	}

	return nil
}

// transferTokens transfers tokens to a user based on source chain and project
// For Avalanche deposits -> Mint FeTi70 on Redbelly (backend minting)
// For Redbelly Ferrox (151) -> Mint Ferrox on Redbelly (backend minting)
// For Redbelly LUCA (151/153) -> Contract handles minting on blockchain
// For XDC deposits (50/51) -> Contract handles minting on blockchain
func (s *VaultBlockchainListener) transferTokens(sourceChainID int64, userAddress string, usdAmount *big.Int, eventTxHash string, sourceContractAddress string) (string, float64, string, error) {
	// XDC (chain 50/51): Contract mints automatically on blockchain
	if sourceChainID == 50 || sourceChainID == 51 {
		log.Printf("🎯 [XDC Ferrox] Contract handles minting automatically for chain %d - skipping backend mint", sourceChainID)
		return "", 0, "", nil
	}

	// Redbelly chain (151 mainnet, 153 testnet): Check if LUCA vault
	if sourceChainID == 151 || sourceChainID == 153 {
		lucaContractAddr := viper.GetString("vault.chains.redbelly_luca.contract_address")
		if strings.EqualFold(sourceContractAddress, lucaContractAddr) {
			log.Printf("🎯 [LUCA Deposit] Contract handles minting automatically for chain %d (contract: %s) - skipping backend mint", sourceChainID, sourceContractAddress)
			return "", 0, "", nil
		}
		// If not LUCA contract, it's Ferrox on Redbelly → Continue to backend minting below
		log.Printf("🔥 [Redbelly Ferrox] Backend minting required for chain %d (contract: %s)", sourceChainID, sourceContractAddress)
	}

	// Determine which token contract to use based on source chain and project
	// (Avalanche and Redbelly mint on Redbelly network)
	var tokenContractAddr common.Address
	var tokenName string

	switch sourceChainID {
	case 43113, 43114: // Avalanche Fuji or Mainnet -> Mint FeTi70 on Redbelly
		tokenContractAddr = common.HexToAddress(viper.GetString("redbelly.feti70_contract_address"))
		tokenName = "FeTi70"

	case 151, 153: // Redbelly Ferrox (mainnet 151 or testnet 153) -> Mint Ferrox on Redbelly
		// NOTE: LUCA contract deposits (151/153) are handled above and return early (blockchain minting)
		// If we reach here, it's definitely Ferrox vault that needs backend minting
		tokenContractAddr = common.HexToAddress(viper.GetString("redbelly.ferrox_contract_address"))
		tokenName = "Ferrox"
		log.Printf("🔗 [Token Transfer] Redbelly Ferrox project detected - minting Ferrox tokens on Redbelly (chain %d)", sourceChainID)

	default:
		return "", 0, "", fmt.Errorf("unsupported source chain ID: %d", sourceChainID)
	}

	log.Printf("🚀 [Token Transfer] Starting token transfer process...")
	log.Printf("🔧 [Token Transfer] Source Chain: %d, Token: %s, Contract: %s", sourceChainID, tokenName, tokenContractAddr.Hex())
	log.Printf("🔧 [Token Transfer] Redbelly client status: %v, config status: %v", s.redbellyClient != nil, s.redbellyConfig != nil)

	if s.redbellyClient == nil {
		log.Printf("❌ [Token Transfer] Redbelly client is nil - network not configured")
		return "", 0, "", fmt.Errorf("Redbelly client not configured")
	}
	if s.redbellyConfig == nil {
		log.Printf("❌ [Token Transfer] Redbelly config is nil - network not configured")
		return "", 0, "", fmt.Errorf("Redbelly config not configured")
	}

	// 🔐 Lazy-load the signing key from Secret Manager if missing
	if s.redbellyConfig.PrivateKey == nil {
		log.Printf("🗝️  [Token Transfer] Private key is nil — loading from Secret Manager...")

		projectID := viper.GetString("gcp.project_id")        // e.g. "ferrox-production"
		secretName := viper.GetString("redbelly.secret_name") // e.g. "redbelly-fe-signer"
		if projectID == "" || secretName == "" {
			return "", 0, "", fmt.Errorf("missing Secret Manager config: set gcp.project_id and redbelly.secret_name")
		}

		// Build full resource name: projects/{project}/secrets/{secret}/versions/latest
		secretRes := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", projectID, secretName)

		ctx := context.Background()
		smClient, err := secretmanager.NewClient(ctx)
		if err != nil {
			return "", 0, "", fmt.Errorf("secretmanager.NewClient: %w", err)
		}
		defer smClient.Close()

		resp, err := smClient.AccessSecretVersion(ctx, &secretspb.AccessSecretVersionRequest{Name: secretRes})
		if err != nil {
			return "", 0, "", fmt.Errorf("access secret version %q: %w", secretRes, err)
		}
		data := strings.TrimSpace(string(resp.Payload.Data))

		// Try HEX first (0x… or plain)
		hexStr := strings.TrimPrefix(data, "0x")
		if isHex := func(s string) bool {
			if len(s) == 0 {
				return false
			}
			for _, c := range s {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
					return false
				}
			}
			return true
		}; isHex(hexStr) {
			pk, err := crypto.HexToECDSA(hexStr)
			if err != nil {
				return "", 0, "", fmt.Errorf("parse HEX private key from Secret Manager: %w", err)
			}
			s.redbellyConfig.PrivateKey = pk
			log.Printf("✅ [Token Transfer] Loaded HEX signer key from Secret Manager (%s/%s)", projectID, secretName)
		} else {
			// Try PEM (PKCS#8 or EC PRIVATE KEY)
			block, _ := pem.Decode([]byte(data))
			if block == nil {
				return "", 0, "", errors.New("secret value is neither hex nor PEM")
			}
			// PKCS#8?
			if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
				if ec, ok := k.(*ecdsa.PrivateKey); ok {
					s.redbellyConfig.PrivateKey = ec
					log.Printf("✅ [Token Transfer] Loaded PKCS#8 PEM signer key from Secret Manager (%s/%s)", projectID, secretName)
				}
			}
			// If still nil, try SEC1 EC
			if s.redbellyConfig.PrivateKey == nil {
				ec, err := x509.ParseECPrivateKey(block.Bytes)
				if err != nil {
					return "", 0, "", fmt.Errorf("parse PEM EC private key from Secret Manager: %w", err)
				}
				s.redbellyConfig.PrivateKey = ec
				log.Printf("✅ [Token Transfer] Loaded EC PEM signer key from Secret Manager (%s/%s)", projectID, secretName)
			}
		}

		log.Printf("👤 [Token Transfer] Deployer Address: %s", crypto.PubkeyToAddress(s.redbellyConfig.PrivateKey.PublicKey).Hex())
	}

	log.Printf("✅ [Token Transfer] Redbelly network is properly configured")
	log.Printf("🌐 [Token Transfer] RPC URL: %s", s.redbellyConfig.RPCUrl)
	log.Printf("📄 [Token Transfer] Token Contract Address: %s (%s)", tokenContractAddr.Hex(), tokenName)
	log.Printf("🔗 [Token Transfer] Chain ID: %s", s.redbellyConfig.ChainID.String())

	log.Printf("🔄 Transferring %s tokens on Redbelly network...", tokenName)
	log.Printf("User address: %s", userAddress)
	log.Printf("USD amount: %s", usdAmount.String())
	log.Printf("Source event tx: %s", eventTxHash)

	// Parse contract ABI
	log.Printf("📋 [Token Transfer] Parsing contract ABI...")
	parsedABI, err := abi.JSON(strings.NewReader(feti70ContractABI))
	if err != nil {
		log.Printf("❌ [Token Transfer] Failed to parse ABI: %v", err)
		return "", 0, "", fmt.Errorf("failed to parse %s ABI: %v", tokenName, err)
	}
	log.Printf("✅ [Token Transfer] ABI parsed successfully")

	// Create contract instance
	log.Printf("🏗️ [Token Transfer] Creating contract instance...")
	tokenContract := bind.NewBoundContract(tokenContractAddr, parsedABI, s.redbellyClient, s.redbellyClient, s.redbellyClient)
	log.Printf("✅ [Token Transfer] Contract instance created successfully")

	// Get token decimals
	log.Printf("🔢 [Token Transfer] Getting token decimals...")
	var decimals uint8
	err = tokenContract.Call(&bind.CallOpts{}, &[]interface{}{&decimals}, "decimals")
	if err != nil {
		log.Printf("❌ [Token Transfer] Failed to get decimals: %v", err)
		return "", 0, "", fmt.Errorf("failed to get %s decimals: %v", tokenName, err)
	}
	log.Printf("✅ [Token Transfer] Token decimals retrieved: %d", decimals)

	// Calculate token amount (1:1 with USD dollars)
	usdInDollars := new(big.Int).Div(usdAmount, big.NewInt(1000000)) // USDC has 6 decimals
	tokenAmount := new(big.Int).Mul(usdInDollars, new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil))
	log.Printf("Amount to transfer: %s %s (raw: %s)", usdInDollars.String(), tokenName, tokenAmount.String())

	// Check deployer's balance
	deployerAddr := crypto.PubkeyToAddress(s.redbellyConfig.PrivateKey.PublicKey)
	var deployerBalance *big.Int
	err = tokenContract.Call(&bind.CallOpts{}, &[]interface{}{&deployerBalance}, "balanceOf", deployerAddr)
	if err != nil {
		return "", 0, "", fmt.Errorf("failed to get deployer balance: %v", err)
	}
	log.Printf("Deployer %s balance: %s", tokenName, deployerBalance.String())

	if deployerBalance.Cmp(tokenAmount) < 0 {
		return "", 0, "", fmt.Errorf("deployer does not have enough %s tokens: need %s, have %s",
			tokenName, tokenAmount.String(), deployerBalance.String())
	}

	// Create transaction options
	auth, err := bind.NewKeyedTransactorWithChainID(s.redbellyConfig.PrivateKey, s.redbellyConfig.ChainID)
	if err != nil {
		return "", 0, "", fmt.Errorf("failed to create transactor: %v", err)
	}

	// Set gas
	auth.GasLimit = 200000
	gasPrice, err := s.redbellyClient.SuggestGasPrice(context.Background())
	if err != nil {
		log.Printf("⚠️ Failed to get gas price, using default: %v", err)
		auth.GasPrice = big.NewInt(20000000000) // 20 gwei
	} else {
		auth.GasPrice = gasPrice
	}

	// Transfer tokens
	log.Printf("💸 [Token Transfer] Initiating token transfer transaction...")
	log.Printf("🎯 [Token Transfer] Target address: %s", userAddress)
	log.Printf("💰 [Token Transfer] Transfer amount: %s %s tokens", tokenAmount.String(), tokenName)
	log.Printf("⛽ [Token Transfer] Gas limit: %d, Gas price: %s", auth.GasLimit, auth.GasPrice.String())

	userAddr := common.HexToAddress(userAddress)
	tx, err := tokenContract.Transact(auth, "transfer", userAddr, tokenAmount)
	if err != nil {
		log.Printf("❌ [Token Transfer] Transaction failed: %v", err)
		return "", 0, "", fmt.Errorf("failed to transfer %s tokens: %v", tokenName, err)
	}
	log.Printf("📋 [Token Transfer] Transaction submitted with hash: %s", tx.Hash().Hex())

	// Return values (hash + amount in float + token name)
	mintTxHash := tx.Hash().Hex()
	tokenAmountFloat, _ := new(big.Float).SetInt(usdInDollars).Float64()

	log.Printf("✅ %s tokens transferred successfully!", tokenName)
	log.Printf("Transaction hash: %s", tx.Hash().Hex())
	log.Printf("User: %s", userAddress)
	log.Printf("Amount: %s %s", usdInDollars.String(), tokenName)

	// Wait for confirmation
	receipt, err := bind.WaitMined(context.Background(), s.redbellyClient, tx)
	if err != nil {
		log.Printf("⚠️ Transaction sent but failed to get receipt: %v", err)
		return mintTxHash, tokenAmountFloat, tokenName, nil // Return hash even if receipt fails
	}

	if receipt.Status == 1 {
		log.Printf("✅ Transaction confirmed successfully in block %d", receipt.BlockNumber.Uint64())
	} else {
		return "", 0, "", fmt.Errorf("transaction failed with status %d", receipt.Status)
	}

	// Verify user's new balance (best-effort)
	var userBalance *big.Int
	err = tokenContract.Call(&bind.CallOpts{}, &[]interface{}{&userBalance}, "balanceOf", userAddr)
	if err != nil {
		log.Printf("⚠️ Failed to verify user balance: %v", err)
	} else {
		userBalanceInTokens := new(big.Int).Div(userBalance, new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil))
		log.Printf("User's new %s balance: %s %s", tokenName, userBalanceInTokens.String(), tokenName)
	}

	return mintTxHash, tokenAmountFloat, tokenName, nil
}

// updateVaultPositionWithMintHash updates the VaultPosition record with Redbelly mint information
func (s *VaultBlockchainListener) updateVaultPositionWithMintHash(positionID uint64, chainID int64, userAddress string, contractAddress string, mintHash string, tokenAmount float64, tokenName string, depositTxHash string, depositBlockNumber uint64) {
	log.Printf("💾 [DB Update] Starting VaultPosition update with transaction data...")
	log.Printf("🎯 [DB Update] Position ID: %d", positionID)
	log.Printf("🏔️ [DB Update] Source Deposit Tx: %s (Block: %d)", depositTxHash, depositBlockNumber)
	log.Printf("🔗 [DB Update] Mint Hash: %s", mintHash)
	log.Printf("💰 [DB Update] Token Amount: %.2f %s", tokenAmount, tokenName)

	// Find and update the VaultPosition record with multiple fields to ensure exact match
	filter := bson.M{
		"position_id":      int64(positionID), // Convert to int64 to match MongoDB Long type
		"chain_id":         chainID,
		"user_address":     strings.ToLower(userAddress),
		"contract_address": strings.ToLower(contractAddress),
	}
	now := time.Now()
	log.Printf("🔍 [DB Update] Searching for VaultPosition - ID: %d, Chain: %d, User: %s", positionID, chainID, strings.ToLower(userAddress))

	// Use new generic mint_* field names instead of redbelly_* to avoid confusion
	update := bson.M{
		"$set": bson.M{
			"deposit_tx_hash":      depositTxHash,
			"deposit_block_number": depositBlockNumber,
			"mint_hash":            mintHash,
			"mint_tx_status":       "confirmed",
			"mint_tx_time":         &now,
			"mint_token_amount":    tokenAmount,
			"mint_token_name":      tokenName,
			"updated_at":           now,
		},
	}

	log.Printf("🔄 [DB Update] Executing database update...")
	log.Printf("🔍 [DB Update] Update document: %+v", update)
	err := repository.IRepo.UpdateOne("vault_positions", filter, update, false)
	if err != nil {
		log.Printf("❌ [DB Update] Failed to update VaultPosition %d: %v", positionID, err)
		log.Printf("🚑 [DB Update] Error details - Filter: %+v", filter)
	} else {
		log.Printf("✅ [DB Update] Successfully updated VaultPosition %d with transaction data", positionID)
		log.Printf("💾 [DB Update] Updated fields: deposit_tx=%s, mint_hash=%s, status=confirmed, amount=%.2f", depositTxHash, mintHash, tokenAmount)

		// Verify the update by reading the document back
		var updatedPosition models.VaultPosition
		verifyErr := repository.IRepo.FindOneWhere("vault_positions", filter, &updatedPosition)
		if verifyErr != nil {
			log.Printf("⚠️ [DB Update] Could not verify update: %v", verifyErr)
		} else {
			log.Printf("🔍 [DB Update] Verification - DepositTxHash: '%s'", updatedPosition.DepositTxHash)
			log.Printf("🔍 [DB Update] Verification - DepositBlockNumber: %d", updatedPosition.DepositBlockNumber)
			log.Printf("🔍 [DB Update] Verification - MintHash: '%s'", updatedPosition.MintHash)
			log.Printf("🔍 [DB Update] Verification - MintTxStatus: '%s'", updatedPosition.MintTxStatus)
			log.Printf("🔍 [DB Update] Verification - MintTokenAmount: %.2f %s", updatedPosition.MintTokenAmount, updatedPosition.MintTokenName)
		}
	}
}

// Start initializes the vault blockchain listener for all configured chains
func (s *VaultBlockchainListener) Start() error {
	// Get vault contract configurations from viper
	chainConfigs := viper.GetStringMap("vault.chains")

	if len(chainConfigs) == 0 {
		log.Println("No vault chain configurations found")
		return fmt.Errorf("no vault chain configurations found")
	}

	// Start monitoring each configured chain
	for chainIDStr, configInterface := range chainConfigs {
		chainConfig, ok := configInterface.(map[string]interface{})
		if !ok {
			log.Printf("Invalid chain config for %s", chainIDStr)
			continue
		}

		// Get RPC URLs (supports both single URL and array of URLs)
		rpcURLs := utils.GetRPCURLs(chainConfig)
		if len(rpcURLs) == 0 {
			log.Printf("Missing RPC URL for chain %s", chainIDStr)
			continue
		}

		contractAddress, ok := chainConfig["contract_address"].(string)
		if !ok {
			log.Printf("Missing contract address for chain %s", chainIDStr)
			continue
		}

		chainName, _ := chainConfig["name"].(string)
		if chainName == "" {
			chainName = chainIDStr
		}

		// Convert chain ID to int64
		// First, try to get chain_id from config (allows override)
		var chainID int64
		if configChainID, ok := chainConfig["chain_id"].(int); ok {
			chainID = int64(configChainID)
			log.Printf("Using chain_id from config for %s: %d", chainIDStr, chainID)
		} else if configChainID, ok := chainConfig["chain_id"].(float64); ok {
			chainID = int64(configChainID)
			log.Printf("Using chain_id from config for %s: %d", chainIDStr, chainID)
		} else {
			// Fallback to hardcoded chain IDs if not specified in config
			switch chainIDStr {
			case "polygon":
				chainID = 137
			case "holesky":
				chainID = 17000
			case "fuji":
				chainID = 43113
			case "avalanche":
				chainID = 43114
			case "bsc":
				chainID = 56
			case "ethereum":
				chainID = 1
			case "redbelly":
				chainID = 153 // Redbelly testnet chain ID (default)
			case "redbelly_luca":
				chainID = 153 // Redbelly testnet chain ID (default)
			case "xdc":
				chainID = 51 // XDC Apothem testnet (mainnet is 50, default)
			case "xdc_compute_labs":
				chainID = 51 // XDC Apothem testnet - same as XDC (mainnet is 50)
			default:
				log.Printf("Unknown chain: %s and no chain_id in config", chainIDStr)
				continue
			}
			log.Printf("Using default chain_id for %s: %d", chainIDStr, chainID)
		}

		config := models.VaultChainConfig{
			ChainID:         chainID,
			Name:            chainName,
			RPCUrl:          rpcURLs[0], // Use first URL for initial config (will be tried with failover)
			RPCUrls:         rpcURLs,    // Store all URLs for failover
			ContractAddress: contractAddress,
		}

		log.Printf("Starting vault monitoring for chain %d (%s) with %d RPC endpoints", config.ChainID, config.Name, len(rpcURLs))
		if err := s.StartMonitoringChain(config); err != nil {
			log.Printf("Warning: Failed to start vault monitoring chain %d (%s): %v", config.ChainID, config.Name, err)
			// Continue with other chains
		}
	}

	return nil
}

// StartMonitoringChain starts monitoring a specific blockchain for vault events
func (s *VaultBlockchainListener) StartMonitoringChain(config models.VaultChainConfig) error {
	chainID := config.ChainID

	// Check if we're already monitoring this chain
	if _, exists := s.clients[chainID]; exists {
		// Chain is already being monitored, just add the new contract address
		contractAddr := common.HexToAddress(config.ContractAddress)

		// Check if contract is already being monitored
		for _, addr := range s.contractAddresses[chainID] {
			if addr == contractAddr {
				log.Printf("Contract %s already being monitored on chain %d", contractAddr.Hex(), chainID)
				return nil
			}
		}

		// Add new contract to monitoring list
		s.contractAddresses[chainID] = append(s.contractAddresses[chainID], contractAddr)
		log.Printf("✅ Added contract %s to existing monitoring on chain %d (total contracts: %d)",
			contractAddr.Hex(), chainID, len(s.contractAddresses[chainID]))
		return nil
	}

	// Connect to the blockchain with automatic failover
	rpcURLs := config.RPCUrls
	if len(rpcURLs) == 0 {
		// Fallback to single URL if no array provided
		rpcURLs = []string{config.RPCUrl}
	}

	client, connectedURL, err := utils.ConnectWithFailover(rpcURLs, config.Name, chainID)
	if err != nil {
		return fmt.Errorf("failed to connect to vault blockchain after trying %d RPC URLs: %v", len(rpcURLs), err)
	}

	log.Printf("✅ [Blockchain Listener] Connected to %s (Chain %d) using RPC: %s", config.Name, chainID, connectedURL)

	// Store the client and contract address
	s.clients[chainID] = client
	s.stopChannels[chainID] = make(chan struct{})
	s.contractAddresses[chainID] = []common.Address{common.HexToAddress(config.ContractAddress)}

	// Get the last processed block for vault events
	fromBlock, err := s.getLastProcessedVaultBlock(chainID)
	if err != nil {
		log.Printf("No vault sync state found for chain %d: %v", chainID, err)

		// Get current block as fallback
		currentBlock, err := client.BlockNumber(context.Background())
		if err != nil {
			client.Close()
			return fmt.Errorf("failed to get current block number: %v", err)
		}

		// Start from recent blocks or block 0
		if currentBlock > 1000 {
			fromBlock = new(big.Int).SetUint64(currentBlock - 1000) // Start from 1000 blocks ago
		} else {
			fromBlock = new(big.Int).SetUint64(0)
		}

		log.Printf("No vault sync state found for chain %d, starting from block %s",
			chainID, fromBlock.String())

		// Initialize the sync state
		now := time.Now()
		initialState := models.VaultSyncState{
			ChainID:            chainID,
			LastBlockProcessed: fromBlock.Int64() - 1, // Will be updated immediately
			CreatedAt:          now,
			UpdatedAt:          now,
		}

		if err := repository.IRepo.Create("vault_sync_states", &initialState); err != nil {
			log.Printf("Warning: Failed to create initial vault sync state for chain %d: %v", chainID, err)
		}
	} else {
		log.Printf("Resuming vault events from block %s for chain %d",
			fromBlock.String(), chainID)
	}

	// Start the monitoring goroutine
	s.wg.Add(1)
	go s.monitorVaultEvents(chainID, fromBlock, s.stopChannels[chainID])

	log.Printf("Started monitoring vault events for chain %d from block %s",
		chainID, fromBlock.String())
	return nil
}

// Stop terminates all vault monitoring routines
func (s *VaultBlockchainListener) Stop() {
	log.Println("Stopping vault blockchain listener...")

	// Signal all monitoring goroutines to stop
	for chainID, stopChan := range s.stopChannels {
		close(stopChan)
		log.Printf("Sent stop signal to vault chain %d", chainID)
	}

	// Wait for all goroutines to exit
	s.wg.Wait()

	// Close all client connections
	for chainID, client := range s.clients {
		client.Close()
		log.Printf("Closed vault connection to chain %d", chainID)
		delete(s.clients, chainID)
		delete(s.stopChannels, chainID)
	}

	// Close Redbelly client
	if s.redbellyClient != nil {
		s.redbellyClient.Close()
		log.Println("Closed Redbelly connection")
	}

	log.Println("Vault blockchain listener stopped")
}

// Constants for vault event monitoring
const (
	VaultDefaultBatchSize     = 50  // Increased from 50 to catch up faster
	VaultMaxBatchSize         = 100 // Increased from 100 for quicker sync
	VaultMinBatchSize         = 1
	VaultDefaultConfirmations = 12
)

// monitorVaultEvents monitors vault contract events with enhanced debugging
func (s *VaultBlockchainListener) monitorVaultEvents(chainID int64, fromBlock *big.Int, stopChan chan struct{}) {
	defer s.wg.Done()

	// Add clear chain identification banner
	chainBanner := ""
	if chainID == 151 || chainID == 153 {
		chainBanner = fmt.Sprintf("🔴🔴🔴 REDBELLY CHAIN %d 🔴🔴🔴", chainID)
	} else if chainID == 43114 {
		chainBanner = "🔵🔵🔵 AVALANCHE CHAIN 43114 🔵🔵🔵"
	} else if chainID == 50 || chainID == 51 {
		chainBanner = fmt.Sprintf("🟢🟢🟢 XDC CHAIN %d 🟢🟢🟢", chainID)
	}

	log.Printf("🚀 Vault event monitoring started for chain %d from block %s", chainID, fromBlock.String())
	log.Printf("========================================")
	log.Printf(">>> %s <<<", chainBanner)
	log.Printf("========================================")

	client := s.clients[chainID]
	ctx := context.Background()

	// Get chain-specific block confirmations
	var confirmations int64
	chainName := ""

	// Determine chain name based on chainID
	switch chainID {
	case 43114, 43113: // Avalanche mainnet and testnet
		chainName = "avalanche"
	case 151, 153: // RedBelly
		chainName = "redbelly"
	case 50, 51: // XDC mainnet and testnet
		chainName = "xdc"
	default:
		// For other chains, could add more cases as needed
		chainName = fmt.Sprintf("chain_%d", chainID)
	}

	// Try to get chain-specific confirmations first
	chainSpecificKey := fmt.Sprintf("vault.chains.%s.block_confirmations", chainName)
	confirmations = int64(viper.GetInt(chainSpecificKey))

	// If not found, fall back to global setting
	if confirmations <= 0 {
		confirmations = int64(viper.GetInt("vault.block_confirmations"))
	}

	// If still not set, use default
	if confirmations <= 0 {
		confirmations = VaultDefaultConfirmations
	}

	log.Printf("🔧 Chain %d (%s) config: confirmations=%d", chainID, chainName, confirmations)

	// UPDATED: Event signatures for vault contract with single status system
	// Ferrox vaults (with tier and rolloverEnabled)
	vaultDepositSig := crypto.Keccak256Hash([]byte("VaultDeposit(address,uint256,uint8,uint256,uint256,uint256,bool,uint256,uint256,string,string,uint256,uint256)"))
	// 129Knots deposit signature (without rolloverEnabled)
	knotsVaultDepositSig := crypto.Keccak256Hash([]byte("VaultDeposit(address,uint256,uint8,uint256,uint256,uint256,uint256,uint256,string,string,uint256,uint256)"))
	// Raze Reserve deposit signature (different param order, no principalAmount)
	razeReserveVaultDepositSig := crypto.Keccak256Hash([]byte("VaultDeposit(address,uint256,uint8,uint256,uint256,uint256,string,string,uint256,uint256,bool,uint256)"))
	vaultRedeemedSig := crypto.Keccak256Hash([]byte("VaultRedeemed(address,uint256,uint256,uint256,uint256,uint256,uint8,string,string,uint256,uint256,uint256)"))
	redemptionRequestedSig := crypto.Keccak256Hash([]byte("RedemptionRequested(address,uint256,uint256,uint256,uint8,uint256,uint256)"))
	positionStatusUpdatedSig := crypto.Keccak256Hash([]byte("PositionStatusUpdated(address,uint256,uint8,uint8,uint256)")) // CHANGED: Updated signature
	vaultRolledOverSig := crypto.Keccak256Hash([]byte("VaultRolledOver(address,uint256,uint256,uint256,uint8)"))
	// Raze Reserve: VaultRedeemed (redeemPosition pays out directly → status 3 Completed)
	razeReserveVaultRedeemedSig := crypto.Keccak256Hash([]byte("VaultRedeemed(address,uint256,uint256,uint256,uint256,uint8,string,string,uint256,uint256,uint256,uint256)"))
	contractPausedSig := crypto.Keccak256Hash([]byte("ContractPaused(address,uint256)"))
	contractUnpausedSig := crypto.Keccak256Hash([]byte("ContractUnpaused(address,uint256)"))
	xtfTokensTransferredSig := crypto.Keccak256Hash([]byte("XTFTokensTransferred(address,address,uint256,uint256,uint256)"))

	// Compute Labs: VaultDeposit event signature (without tier and rolloverEnabled, with apyRate instead of arrRate)
	computeLabsVaultDepositSig := crypto.Keccak256Hash([]byte("VaultDeposit(address,uint256,uint256,uint256,uint256,uint256,uint256,string,string,uint256,uint256)"))
	// Compute Labs: VaultRedeemed event signature (without tier)
	computeLabsVaultRedeemedSig := crypto.Keccak256Hash([]byte("VaultRedeemed(address,uint256,uint256,uint256,uint256,uint256,string,string,uint256,uint256)"))

	// Compute Labs: DistributionClaimed event signature (monthly yield claims)
	// Event: DistributionClaimed(address user, uint256 positionId, uint256 claimableYield, uint256 distributionTax, uint256 timestamp)
	distributionClaimedSig := crypto.Keccak256Hash([]byte("DistributionClaimed(address,uint256,uint256,uint256,uint256)"))

	// Compute Labs: Distribution and Buyout event signatures
	distributionScheduleInitiatedSig := crypto.Keccak256Hash([]byte("DistributionScheduleInitiated(address,uint256,uint256)"))
	buyoutScheduledSig := crypto.Keccak256Hash([]byte("BuyoutScheduled(address,uint256,uint256)"))
	buyoutExecutedSig := crypto.Keccak256Hash([]byte("BuyoutExecuted(address,uint256,uint256)"))

	// Compute Labs: CLGPU Token minting event signature (similar to XTFTokensTransferred for Ferrox US)
	clgpuTokensTransferredSig := crypto.Keccak256Hash([]byte("CLGPUTokensTransferred(address,address,uint256,uint256,uint256)"))

	// Compute Labs: Vault closing/reopening events
	vaultClosedToNewInvestmentsSig := crypto.Keccak256Hash([]byte("VaultClosedToNewInvestments(address,uint256)"))
	vaultReopenedSig := crypto.Keccak256Hash([]byte("VaultReopened(address,uint256)"))

	currentBlock := new(big.Int).Set(fromBlock)
	batchSize := VaultDefaultBatchSize

	// Add a startup delay to ensure all services are ready
	time.Sleep(2 * time.Second)

	log.Printf("📍 Starting vault monitoring loop for chain %d from block %s", chainID, currentBlock.String())

	// Add a counter for debugging stuck issues
	loopCounter := 0
	lastProgressTime := time.Now()

	for {
		select {
		case <-stopChan:
			log.Printf("🛑 Stopping vault event monitoring for chain %d at block %s", chainID, currentBlock.String())
			return
		default:
			loopCounter++

			// Debug log every 100 iterations to track if we're stuck
			if loopCounter%100 == 0 {
				log.Printf("🔄 Vault monitoring loop iteration %d for chain %d, current block: %s",
					loopCounter, chainID, currentBlock.String())
			}

			// Get latest block with timeout context
			ctxWithTimeout, cancel := context.WithTimeout(ctx, 10*time.Second)
			latestBlock, err := client.BlockNumber(ctxWithTimeout)
			cancel()

			if err != nil {
				log.Printf("❌ Error getting latest block number for vault chain %d: %v. Waiting...", chainID, err)
				time.Sleep(2 * time.Second)
				continue
			}

			// Clear chain indicator for each iteration
			chainIndicator := ""
			if chainID == 151 || chainID == 153 {
				chainIndicator = "🔴 REDBELLY"
			} else if chainID == 153 {
				chainIndicator = "🟠 REDBELLY-TEST"
			} else if chainID == 43114 {
				chainIndicator = "🔵 AVALANCHE"
			} else if chainID == 50 || chainID == 51 {
				chainIndicator = "🟢 XDC"
			}

			log.Printf("🔍 %s Chain %d status: latest=%d, current=%s, confirmations=%d",
				chainIndicator, chainID, latestBlock, currentBlock.String(), confirmations)

			// Calculate confirmed block
			confirmedBlock := int64(latestBlock) - confirmations
			if confirmedBlock <= 0 {
				log.Printf("⏳ Not enough blocks for vault confirmation on chain %d (latest: %d, need: %d), waiting...",
					chainID, latestBlock, confirmations)
				time.Sleep(3 * time.Second)
				continue
			}

			log.Printf("✅ %s Chain %d confirmed block: %d, current processing block: %s",
				chainIndicator, chainID, confirmedBlock, currentBlock.String())

			// Check if we've reached the confirmed block
			if currentBlock.Int64() >= confirmedBlock {
				// Check if we've been stuck for too long
				if time.Since(lastProgressTime) > 2*time.Minute {
					log.Printf("⚠️ Vault monitoring appears stuck on chain %d. Current: %s, Confirmed: %d. Force advancing by 1 block.",
						chainID, currentBlock.String(), confirmedBlock)
					currentBlock = new(big.Int).SetInt64(confirmedBlock - 10) // Go back 10 blocks and retry
					lastProgressTime = time.Now()
					continue
				}

				log.Printf("⏸️ Reached confirmed vault block %d on chain %d (current: %s), waiting for new blocks...",
					confirmedBlock, chainID, currentBlock.String())
				time.Sleep(2 * time.Second)
				continue
			}

			// Reset last progress time since we're making progress
			lastProgressTime = time.Now()

			// Calculate batch size
			blocksAvailable := confirmedBlock - currentBlock.Int64()
			if blocksAvailable < int64(batchSize) {
				batchSize = int(blocksAvailable)
			} else if blocksAvailable > int64(VaultMaxBatchSize) {
				batchSize = VaultMaxBatchSize
			}

			if batchSize <= 0 {
				log.Printf("⚠️ Invalid batch size %d for chain %d, setting to 1", batchSize, chainID)
				batchSize = 1
			}

			endBlock := new(big.Int).Add(currentBlock, big.NewInt(int64(batchSize-1)))
			if endBlock.Int64() > confirmedBlock {
				endBlock.SetInt64(confirmedBlock)
			}

			log.Printf("🔄 %s Processing vault batch %d blocks from %s to %s on chain %d (available: %d)",
				chainIndicator, batchSize, currentBlock.String(), endBlock.String(), chainID, blocksAvailable)

			var totalEventsProcessed int
			startTime := time.Now()

			// Process vault contract events
			if contracts, ok := s.contractAddresses[chainID]; ok && len(contracts) > 0 {
				log.Printf("🔍 %s Filtering logs for vault contracts: %v", chainIndicator, contracts)

				vaultQuery := ethereum.FilterQuery{
					FromBlock: currentBlock,
					ToBlock:   endBlock,
					Addresses: contracts,
					Topics: [][]common.Hash{{
						computeLabsVaultDepositSig,    // Compute Labs VaultDeposit
						knotsVaultDepositSig,          // 129Knots VaultDeposit
						razeReserveVaultDepositSig,    // Raze Reserve VaultDeposit
						vaultDepositSig,
						vaultRedeemedSig,
						razeReserveVaultRedeemedSig,   // Raze Reserve VaultRedeemed
						computeLabsVaultRedeemedSig,   // Compute Labs VaultRedeemed
						redemptionRequestedSig,
						positionStatusUpdatedSig, // UPDATED: Changed from redemptionStatusUpdatedSig
						vaultRolledOverSig,
						contractPausedSig,
						contractUnpausedSig,
						xtfTokensTransferredSig,          // XDC Ferrox mint event
						distributionClaimedSig,           // Compute Labs monthly distribution claim
						distributionScheduleInitiatedSig, // Compute Labs distribution schedule
						buyoutScheduledSig,               // Compute Labs buyout schedule
						buyoutExecutedSig,                // Compute Labs buyout execution
						clgpuTokensTransferredSig,        // Compute Labs CLGPU token mint event
						vaultClosedToNewInvestmentsSig,   // Compute Labs vault closed event
						vaultReopenedSig,                 // Compute Labs vault reopened event
					}},
				}

				// Add timeout for log filtering
				ctxWithTimeout, cancel := context.WithTimeout(ctx, 30*time.Second)
				vaultLogs, err := client.FilterLogs(ctxWithTimeout, vaultQuery)
				cancel()

				if err != nil {
					log.Printf("❌ Error filtering vault logs for chain %d (blocks %s-%s): %v",
						chainID, currentBlock.String(), endBlock.String(), err)
					if batchSize > VaultMinBatchSize {
						batchSize = batchSize / 2
						log.Printf("🔻 Reduced batch size to %d for chain %d", batchSize, chainID)
						continue
					}
					time.Sleep(2 * time.Second)
					continue
				}

				log.Printf("📊 %s Found %d vault logs for chain %d (blocks %s-%s)",
					chainIndicator, len(vaultLogs), chainID, currentBlock.String(), endBlock.String())

				// Verify and supplement logs from transaction receipts if RPC truncated results
				vaultLogs = s.verifyAndSupplementLogsFromReceipts(
					ctx, client, vaultLogs, contracts, chainIndicator,
					vaultDepositSig, knotsVaultDepositSig, computeLabsVaultDepositSig, vaultRedeemedSig, computeLabsVaultRedeemedSig, redemptionRequestedSig, positionStatusUpdatedSig,
					vaultRolledOverSig, contractPausedSig, contractUnpausedSig, xtfTokensTransferredSig,
					distributionClaimedSig, distributionScheduleInitiatedSig, buyoutScheduledSig, buyoutExecutedSig,
					vaultClosedToNewInvestmentsSig, vaultReopenedSig,
				)

				// IMPORTANT: Process events in two passes to ensure VaultDeposit creates positions
				// before XTFTokensTransferred tries to update them
				// Pass 1: Process VaultDeposit events to create positions
				for i, vLog := range vaultLogs {
					if len(vLog.Topics) == 0 {
						continue
					}
					topicHash := vLog.Topics[0]

					// Check for Ferrox, 129Knots, Compute Labs, and Raze Reserve VaultDeposit signatures
					if topicHash == vaultDepositSig || topicHash == knotsVaultDepositSig || topicHash == computeLabsVaultDepositSig || topicHash == razeReserveVaultDepositSig {
						log.Printf("🔍 %s Processing vault log %d: block=%d, tx=%s, topic=%s",
							chainIndicator, i, vLog.BlockNumber, vLog.TxHash.Hex(), topicHash.Hex())
						if topicHash == computeLabsVaultDepositSig {
							log.Printf("✅ %s Processing Compute Labs VaultDeposit event", chainIndicator)
						} else if topicHash == knotsVaultDepositSig {
							log.Printf("✅ %s Processing 129Knots VaultDeposit event", chainIndicator)
						} else if topicHash == razeReserveVaultDepositSig {
							log.Printf("✅ %s Processing Raze Reserve VaultDeposit event", chainIndicator)
						} else {
							log.Printf("✅ %s Processing Ferrox VaultDeposit event", chainIndicator)
						}
						s.processVaultDepositEvent(chainID, vLog)
						totalEventsProcessed++
					}
				}

				// Pass 2: Process all other events that may update positions
				for i, vLog := range vaultLogs {
					if len(vLog.Topics) == 0 {
						log.Printf("⚠️ Vault log %d has no topics, skipping", i)
						continue
					}
					topicHash := vLog.Topics[0]

					// Skip VaultDeposit signatures since we processed them in pass 1
					if topicHash == vaultDepositSig || topicHash == knotsVaultDepositSig || topicHash == computeLabsVaultDepositSig || topicHash == razeReserveVaultDepositSig {
						continue
					}

					log.Printf("🔍 %s Processing vault log %d: block=%d, tx=%s, topic=%s",
						chainIndicator, i, vLog.BlockNumber, vLog.TxHash.Hex(), topicHash.Hex())

					switch topicHash {
					case vaultRedeemedSig, computeLabsVaultRedeemedSig:
						if topicHash == computeLabsVaultRedeemedSig {
							log.Printf("✅ %s Processing Compute Labs VaultRedeemed event", chainIndicator)
						} else {
							log.Printf("✅ %s Processing Ferrox VaultRedeemed event", chainIndicator)
						}
						s.processVaultRedeemedEvent(chainID, vLog)
						totalEventsProcessed++
					case distributionClaimedSig:
						log.Printf("✅ %s Processing DistributionClaimed event (Compute Labs)", chainIndicator)
						s.processDistributionClaimedEvent(chainID, vLog)
						totalEventsProcessed++
					case distributionScheduleInitiatedSig:
						log.Printf("✅ %s Processing DistributionScheduleInitiated event (Compute Labs)", chainIndicator)
						s.processDistributionScheduleInitiatedEvent(chainID, vLog)
						totalEventsProcessed++
					case buyoutScheduledSig:
						log.Printf("✅ %s Processing BuyoutScheduled event (Compute Labs)", chainIndicator)
						s.processBuyoutScheduledEvent(chainID, vLog)
						totalEventsProcessed++
					case buyoutExecutedSig:
						log.Printf("✅ %s Processing BuyoutExecuted event (Compute Labs)", chainIndicator)
						s.processBuyoutExecutedEvent(chainID, vLog)
						totalEventsProcessed++
					case clgpuTokensTransferredSig:
						log.Printf("✅ %s Processing CLGPUTokensTransferred event (Compute Labs)", chainIndicator)
						s.processCLGPUTokensTransferredEvent(chainID, vLog)
						totalEventsProcessed++
					case redemptionRequestedSig:
						log.Printf("✅ %s Processing RedemptionRequested event", chainIndicator)
						s.processRedemptionRequestedEvent(chainID, vLog)
						totalEventsProcessed++
					case positionStatusUpdatedSig: // UPDATED: Changed from redemptionStatusUpdatedSig
						log.Printf("✅ %s Processing PositionStatusUpdated event", chainIndicator)
						s.processPositionStatusUpdatedEvent(chainID, vLog) // UPDATED: Changed function name
						totalEventsProcessed++
					case vaultRolledOverSig:
						log.Printf("✅ %s Processing VaultRolledOver event", chainIndicator)
						s.processVaultRolledOverEvent(chainID, vLog)
						totalEventsProcessed++
					case razeReserveVaultRedeemedSig:
						log.Printf("✅ %s Processing Raze Reserve VaultRedeemed event", chainIndicator)
						s.processVaultRedeemedEvent(chainID, vLog)
						totalEventsProcessed++
					case contractPausedSig:
						log.Printf("✅ %s Processing ContractPaused event", chainIndicator)
						s.processContractPausedEvent(chainID, vLog)
						totalEventsProcessed++
					case contractUnpausedSig:
						log.Printf("✅ %s Processing ContractUnpaused event", chainIndicator)
						s.processContractUnpausedEvent(chainID, vLog)
						totalEventsProcessed++
					case vaultClosedToNewInvestmentsSig:
						log.Printf("✅ %s Processing VaultClosedToNewInvestments event (Compute Labs)", chainIndicator)
						s.processVaultClosedEvent(chainID, vLog)
						totalEventsProcessed++
					case vaultReopenedSig:
						log.Printf("✅ %s Processing VaultReopened event (Compute Labs)", chainIndicator)
						s.processVaultReopenedEvent(chainID, vLog)
						totalEventsProcessed++
					case xtfTokensTransferredSig:
						log.Printf("✅ %s Processing XTFTokensTransferred event (XDC mint)", chainIndicator)
						s.processXTFTokensTransferredEvent(chainID, vLog)
						totalEventsProcessed++
					default:
						log.Printf("⚠️ %s Unknown vault event topic: %s", chainIndicator, topicHash.Hex())
					}
				}
			} else {
				log.Printf("⚠️ No vault contracts found for chain %d", chainID)
			}

			processingTime := time.Since(startTime)

			// Update last processed block
			log.Printf("💾 Updating last processed vault block to %s for chain %d", endBlock.String(), chainID)
			if err := s.updateLastProcessedVaultBlock(chainID, endBlock); err != nil {
				log.Printf("❌ Error updating last processed vault block for chain %d: %v", chainID, err)
			} else {
				log.Printf("✅ Successfully updated last processed vault block to %s for chain %d", endBlock.String(), chainID)
			}

			if totalEventsProcessed > 0 {
				log.Printf("✅ %s Processed vault batch %d blocks (%s to %s) on chain %d, found %d events in %v",
					chainIndicator, batchSize, currentBlock.String(), endBlock.String(), chainID, totalEventsProcessed, processingTime)
			} else {
				log.Printf("📊 %s Processed vault blocks %s to %s on chain %d (no events found) in %v",
					chainIndicator, currentBlock.String(), endBlock.String(), chainID, processingTime)
			}

			// Move to next batch
			nextBlock := new(big.Int).Add(endBlock, big.NewInt(1))
			log.Printf("➡️ Moving from block %s to %s for chain %d", currentBlock.String(), nextBlock.String(), chainID)
			currentBlock = nextBlock

			// Adjust batch size dynamically
			if batchSize < VaultDefaultBatchSize && batchSize < VaultMaxBatchSize {
				newBatchSize := batchSize * 2
				if newBatchSize > VaultMaxBatchSize {
					newBatchSize = VaultMaxBatchSize
				}
				if newBatchSize > VaultDefaultBatchSize {
					newBatchSize = VaultDefaultBatchSize
				}
				if newBatchSize != batchSize {
					batchSize = newBatchSize
					log.Printf("🔺 Increased batch size to %d for chain %d", batchSize, chainID)
				}
			}

			// Small delay to prevent overwhelming the RPC
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// getLastProcessedVaultBlock retrieves the last processed block number for vault events
func (s *VaultBlockchainListener) getLastProcessedVaultBlock(chainID int64) (*big.Int, error) {
	var blockInfo models.VaultSyncState
	err := repository.IRepo.FindOneWhere("vault_sync_states",
		bson.M{"chain_id": chainID}, &blockInfo)
	if err != nil {
		return nil, err
	}

	// Start from the NEXT block after the last processed one
	nextBlock := blockInfo.LastBlockProcessed + 1
	log.Printf("Found last processed vault block %d for chain %d, resuming from block %d",
		blockInfo.LastBlockProcessed, chainID, nextBlock)

	return new(big.Int).SetInt64(nextBlock), nil
}

// updateLastProcessedVaultBlock updates the last processed block in the database
func (s *VaultBlockchainListener) updateLastProcessedVaultBlock(chainID int64, blockNumber *big.Int) error {
	now := time.Now()
	filter := bson.M{"chain_id": chainID}
	update := bson.M{
		"$set": bson.M{
			"last_block_processed": blockNumber.Int64(),
			"updated_at":           now,
		},
		"$setOnInsert": bson.M{
			"chain_id":   chainID,
			"created_at": now,
		},
	}

	err := repository.IRepo.Upsert("vault_sync_states", filter, update)
	if err != nil {
		return fmt.Errorf("failed to update last processed vault block: %v", err)
	}

	return nil
}

// Helper function to get status name for logging
func getStatusName(status uint8) string {
	switch status {
	case models.StatusActive:
		return "ACTIVE"
	case models.StatusPending:
		return "PENDING"
	case models.StatusAvailable:
		return "AVAILABLE"
	case models.StatusCompleted:
		return "COMPLETED"
	case models.StatusClaimRequested:
		return "CLAIM_REQUESTED"
	default:
		return "UNKNOWN"
	}
}

// getProjectFromContractAddress determines which project based on vault contract address and chain
// Avalanche deposits -> Untapped project (mints FeTi70)
// Redbelly deposits -> Ferrox or LUCA project (determined by contract address)
// XDC deposits -> Ferrox or Compute Labs project (determined by contract address)
func getProjectFromContractAddress(contractAddress string, chainID int64) string {
	contractAddress = strings.ToLower(strings.TrimSpace(contractAddress))

	switch chainID {
	case 43113, 43114: // Avalanche Fuji or Mainnet
		return "untapped"

	case 151, 153: // Redbelly - check contract address to distinguish Ferrox vs LUCA
		ferroxContract := strings.ToLower(viper.GetString("vault.chains.redbelly.contract_address"))
		lucaContract := strings.ToLower(viper.GetString("vault.chains.redbelly_luca.contract_address"))

		if lucaContract != "" && contractAddress == lucaContract {
			return "luca"
		} else if contractAddress == ferroxContract {
			return "ferrox"
		}
		// Default to ferrox for backward compatibility
		return "ferrox"

	case 50, 51: // XDC Mainnet or Apothem - check contract address to distinguish vaults
		ferroxXDCContract := strings.ToLower(viper.GetString("vault.chains.xdc.contract_address"))
		ferroxUSContract := strings.ToLower(viper.GetString("vault.chains.xdc_ferrox_us.contract_address"))
		computeLabsContract := strings.ToLower(viper.GetString("vault.chains.xdc_compute_labs.contract_address"))
		atlasContract := strings.ToLower(viper.GetString("vault.chains.xdc_atlas.contract_address"))
		knotsContract := strings.ToLower(viper.GetString("vault.chains.xdc_knots.contract_address"))
		razeReserveContract := strings.ToLower(viper.GetString("vault.chains.xdc_raze_reserve.contract_address"))

		if razeReserveContract != "" && contractAddress == razeReserveContract {
			return "raze_reserve" // RAZE Reserve (US only - Reg D 506(c))
		} else if knotsContract != "" && contractAddress == knotsContract {
			return "129knots" // 129Knots Finance (NON_US only - Reg S)
		} else if atlasContract != "" && contractAddress == atlasContract {
			return "atlas" // Atlas Trade (NON_US only - Reg S, BVI)
		} else if computeLabsContract != "" && contractAddress == computeLabsContract {
			return "compute_labs"
		} else if ferroxUSContract != "" && contractAddress == ferroxUSContract {
			return "ferrox" // US investors use same project name, differentiated by user_region
		} else if contractAddress == ferroxXDCContract {
			return "ferrox" // Non-US investors Ferrox vault
		}
		// Default to ferrox for backward compatibility
		return "ferrox"

	default:
		return "unknown"
	}
}

// getUserRegionFromContract determines user region based on contract address
// Returns "US" for US-specific contracts (US Ferrox, Compute Labs)
// Returns "NON_US" for all other contracts (Non-US Ferrox, LUCA, Untapped)
func getUserRegionFromContract(contractAddress string, chainID int64, project string) string {
	contractAddress = strings.ToLower(strings.TrimSpace(contractAddress))

	// Compute Labs is US-only (requires accreditation)
	if project == "compute_labs" {
		return "US"
	}

	// RAZE Reserve is US-only (Reg D 506(c), requires KYC + accreditation)
	if project == "raze_reserve" {
		return "US"
	}

	// Ferrox on XDC: Check if it's the US-specific contract
	if project == "ferrox" && (chainID == 50 || chainID == 51) {
		ferroxUSContract := strings.ToLower(viper.GetString("vault.chains.xdc_ferrox_us.contract_address"))
		if ferroxUSContract != "" && contractAddress == ferroxUSContract {
			return "US"
		}
	}

	// Atlas Trade is NON_US only (Reg S - BVI jurisdiction)
	if project == "atlas" {
		return "NON_US"
	}

	// Default to NON_US for backward compatibility
	// This includes: Non-US Ferrox (XDC + Redbelly), LUCA, Untapped (Avalanche)
	return "NON_US"
}

// getProjectFromChainID determines which project based on source chain (DEPRECATED)
// Use getProjectFromContractAddress instead for proper LUCA support
// Kept for backward compatibility only
func getProjectFromChainID(chainID int64) string {
	switch chainID {
	case 43113, 43114: // Avalanche Fuji or Mainnet
		return "untapped"
	case 151, 153: // Redbelly
		return "ferrox"
	case 50, 51: // XDC Mainnet or Apothem
		return "ferrox"
	default:
		return "unknown"
	}
}

// UPDATED: Event processing functions with single status system

func (s *VaultBlockchainListener) processVaultDepositEvent(chainID int64, eventLog types.Log) {
	log.Printf("[VaultDeposit] Block: %d, Tx: %s, Contract: %s",
		eventLog.BlockNumber, eventLog.TxHash.Hex(), eventLog.Address.Hex())

	// Extract indexed parameters first (needed for duplicate check)
	var userAddress string
	var positionId *big.Int
	if len(eventLog.Topics) >= 2 {
		// Normalize address to lowercase for consistency across all collections
		userAddress = strings.ToLower(common.HexToAddress(eventLog.Topics[1].Hex()).Hex())
	}
	if len(eventLog.Topics) >= 3 {
		positionId = new(big.Int).SetBytes(eventLog.Topics[2][:])
	}

	// Check if this event has already been processed (duplicate check)
	// IMPORTANT: Include both user AND position_id to handle multiple users with same position IDs
	txHash := eventLog.TxHash.Hex()
	var existingEvent models.VaultEvent
	err := repository.IRepo.FindOneWhere("vault_events", bson.M{
		"tx_hash":           txHash,
		"event_type":        "VaultDeposit",
		"params.user":       userAddress,
		"params.positionId": positionId.String(),
	}, &existingEvent)
	if err == nil {
		log.Printf("⚠️ [VaultDeposit] Skipping duplicate event with tx_hash: %s, user: %s, position: %s", txHash, userAddress, positionId.String())
		return
	}

	// Determine project based on contract address and chain ID (supports LUCA on Redbelly)
	project := getProjectFromContractAddress(eventLog.Address.Hex(), chainID)

	// Choose the correct ABI based on project
	var abiToUse string
	var isComputeLabs bool
	var isKnots bool
	var isRazeReserve bool
	if project == "compute_labs" {
		abiToUse = computeLabsVaultABI
		isComputeLabs = true
		log.Printf("🔍 [VaultDeposit] Using Compute Labs ABI for project: %s", project)
	} else if project == "129knots" {
		abiToUse = knotsVaultABI
		isKnots = true
		log.Printf("🔍 [VaultDeposit] Using 129Knots ABI for project: %s", project)
	} else if project == "raze_reserve" {
		abiToUse = razeReserveVaultABI
		isRazeReserve = true
		log.Printf("🔍 [VaultDeposit] Using Raze Reserve ABI for project: %s", project)
	} else {
		abiToUse = vaultContractABI
		log.Printf("🔍 [VaultDeposit] Using Ferrox ABI for project: %s", project)
	}

	// Parse non-indexed parameters using the appropriate ABI
	parsedABI, err := abi.JSON(strings.NewReader(abiToUse))
	if err != nil {
		log.Printf("Error parsing vault ABI: %v", err)
		// Log error to database
		s.errorService.LogEventError(
			chainID, userAddress, "VaultDeposit", models.EventStageParsing,
			models.ErrorTypeABIParse, fmt.Sprintf("Failed to parse vault ABI: %v", err),
			txHash, int64(eventLog.BlockNumber), positionId.String(), models.SeverityCritical,
		)
		return
	}

	// Define structures to match the event parameters exactly
	// Ferrox structure (with tier and rolloverEnabled)
	type FerroxVaultDepositEventData struct {
		Tier            uint8
		OriginalAmount  *big.Int
		PrincipalAmount *big.Int
		TaxAmount       *big.Int
		RolloverEnabled bool
		LockEndTime     *big.Int
		DepositTime     *big.Int
		VaultName       string
		VaultSymbol     string
		ArrRate         *big.Int
		LockPeriodDays  *big.Int
	}

	// Compute Labs structure (without tier and rolloverEnabled, has apyRate)
	type ComputeLabsVaultDepositEventData struct {
		OriginalAmount  *big.Int
		PrincipalAmount *big.Int
		TaxAmount       *big.Int
		LockEndTime     *big.Int
		DepositTime     *big.Int
		VaultName       string
		VaultSymbol     string
		ApyRate         *big.Int
		LockPeriodDays  *big.Int
	}

	// 129Knots structure (without rolloverEnabled)
	type KnotsVaultDepositEventData struct {
		Tier            uint8
		OriginalAmount  *big.Int
		PrincipalAmount *big.Int
		TaxAmount       *big.Int
		LockEndTime     *big.Int
		DepositTime     *big.Int
		VaultName       string
		VaultSymbol     string
		ArrRate         *big.Int
		LockPeriodDays  *big.Int
	}

	// Raze Reserve structure (no principalAmount, different param order, no tax deduction)
	type RazeReserveVaultDepositEventData struct {
		Tier            uint8
		OriginalAmount  *big.Int
		LockEndTime     *big.Int
		DepositTime     *big.Int
		TierName        string
		TierSymbol      string
		LockedApyBps    *big.Int
		LockPeriodDays  *big.Int
		RolloverEnabled bool
		TaxAmount       *big.Int
	}

	// Common fields to use regardless of structure
	var tier uint8
	var originalAmount, principalAmount, taxAmount, lockEndTime, depositTime, arrRate, lockPeriodDays *big.Int
	var vaultName, vaultSymbol string
	var rolloverEnabled bool

	if isRazeReserve {
		var eventData RazeReserveVaultDepositEventData
		err = parsedABI.UnpackIntoInterface(&eventData, "VaultDeposit", eventLog.Data)
		if err != nil {
			log.Printf("Error decoding Raze Reserve VaultDeposit event data: %v", err)
			s.errorService.LogEventError(
				chainID, userAddress, "VaultDeposit", models.EventStageDecoding,
				models.ErrorTypeDecode, fmt.Sprintf("Failed to decode Raze Reserve VaultDeposit event: %v", err),
				txHash, int64(eventLog.BlockNumber), positionId.String(), models.SeverityHigh,
			)
			return
		}
		tier = eventData.Tier
		originalAmount = eventData.OriginalAmount
		principalAmount = eventData.OriginalAmount // No tax deduction, principal = original
		taxAmount = eventData.TaxAmount
		lockEndTime = eventData.LockEndTime
		depositTime = eventData.DepositTime
		vaultName = eventData.TierName
		vaultSymbol = eventData.TierSymbol
		arrRate = eventData.LockedApyBps
		lockPeriodDays = eventData.LockPeriodDays
		rolloverEnabled = eventData.RolloverEnabled
	} else if isComputeLabs {
		var eventData ComputeLabsVaultDepositEventData
		err = parsedABI.UnpackIntoInterface(&eventData, "VaultDeposit", eventLog.Data)
		if err != nil {
			log.Printf("Error decoding Compute Labs VaultDeposit event data: %v", err)
			// Log error to database
			s.errorService.LogEventError(
				chainID, userAddress, "VaultDeposit", models.EventStageDecoding,
				models.ErrorTypeDecode, fmt.Sprintf("Failed to decode Compute Labs VaultDeposit event: %v", err),
				txHash, int64(eventLog.BlockNumber), positionId.String(), models.SeverityHigh,
			)
			return
		}
		// Map Compute Labs fields to common fields
		tier = 0 // Compute Labs doesn't have tiers
		originalAmount = eventData.OriginalAmount
		principalAmount = eventData.PrincipalAmount
		taxAmount = eventData.TaxAmount
		lockEndTime = eventData.LockEndTime
		depositTime = eventData.DepositTime
		vaultName = eventData.VaultName
		vaultSymbol = eventData.VaultSymbol
		arrRate = eventData.ApyRate // Note: Compute Labs uses apyRate
		lockPeriodDays = eventData.LockPeriodDays
		rolloverEnabled = false // Compute Labs doesn't have rollover
	} else if isKnots {
		var eventData KnotsVaultDepositEventData
		err = parsedABI.UnpackIntoInterface(&eventData, "VaultDeposit", eventLog.Data)
		if err != nil {
			log.Printf("Error decoding 129Knots VaultDeposit event data: %v", err)
			s.errorService.LogEventError(
				chainID, userAddress, "VaultDeposit", models.EventStageDecoding,
				models.ErrorTypeDecode, fmt.Sprintf("Failed to decode 129Knots VaultDeposit event: %v", err),
				txHash, int64(eventLog.BlockNumber), positionId.String(), models.SeverityHigh,
			)
			return
		}
		tier = eventData.Tier
		originalAmount = eventData.OriginalAmount
		principalAmount = eventData.PrincipalAmount
		taxAmount = eventData.TaxAmount
		lockEndTime = eventData.LockEndTime
		depositTime = eventData.DepositTime
		vaultName = eventData.VaultName
		vaultSymbol = eventData.VaultSymbol
		arrRate = eventData.ArrRate
		lockPeriodDays = eventData.LockPeriodDays
		rolloverEnabled = false
	} else {
		var eventData FerroxVaultDepositEventData
		err = parsedABI.UnpackIntoInterface(&eventData, "VaultDeposit", eventLog.Data)
		if err != nil {
			log.Printf("Error decoding Ferrox VaultDeposit event data: %v", err)
			// Log error to database
			s.errorService.LogEventError(
				chainID, userAddress, "VaultDeposit", models.EventStageDecoding,
				models.ErrorTypeDecode, fmt.Sprintf("Failed to decode Ferrox VaultDeposit event: %v", err),
				txHash, int64(eventLog.BlockNumber), positionId.String(), models.SeverityHigh,
			)
			return
		}
		// Map Ferrox fields to common fields
		tier = eventData.Tier
		originalAmount = eventData.OriginalAmount
		principalAmount = eventData.PrincipalAmount
		taxAmount = eventData.TaxAmount
		lockEndTime = eventData.LockEndTime
		depositTime = eventData.DepositTime
		vaultName = eventData.VaultName
		vaultSymbol = eventData.VaultSymbol
		arrRate = eventData.ArrRate
		lockPeriodDays = eventData.LockPeriodDays
		rolloverEnabled = eventData.RolloverEnabled
	}

	// Determine user region based on contract address (US vs NON-US)
	userRegion := getUserRegionFromContract(eventLog.Address.Hex(), chainID, project)

	// Create event record using common fields
	event := models.VaultEvent{
		ChainID:         chainID,
		Project:         project,
		BlockNumber:     int64(eventLog.BlockNumber),
		TxHash:          eventLog.TxHash.Hex(),
		EventType:       "VaultDeposit",
		ContractAddress: eventLog.Address.Hex(),
		Params: map[string]interface{}{
			"user":            userAddress,
			"positionId":      positionId.String(),
			"tier":            float64(tier),
			"originalAmount":  originalAmount.String(),
			"principalAmount": principalAmount.String(),
			"taxAmount":       taxAmount.String(),
			"rolloverEnabled": rolloverEnabled,
			"lockEndTime":     lockEndTime.String(),
			"depositTime":     depositTime.String(),
			"vaultName":       vaultName,
			"vaultSymbol":     vaultSymbol,
			"arrRate":         arrRate.String(),
			"lockPeriodDays":  lockPeriodDays.String(),
			"status":          float64(models.StatusActive), // NEW: All deposits start as ACTIVE
			"user_region":     userRegion,                   // ✅ NEW: US vs NON-US differentiation
		},
		CreatedAt: time.Now(),
	}

	// Save event to database
	if err := repository.IRepo.Create("vault_events", &event); err != nil {
		log.Printf("Error saving VaultDeposit event: %v", err)
		// Log error to database
		s.errorService.LogEventError(
			chainID, userAddress, "VaultDeposit", models.EventStageSaving,
			models.ErrorTypeDatabase, fmt.Sprintf("Failed to save VaultDeposit event: %v", err),
			txHash, int64(eventLog.BlockNumber), positionId.String(), models.SeverityHigh,
		)
		return
	}

	// Token minting logic:
	// - XDC Ferrox (chain 50/51): Contract mints automatically on blockchain
	// - LUCA (chain 151/153): Contract mints automatically on blockchain
	// - Redbelly Ferrox (chain 151/153): Backend mints Ferrox tokens
	// - Avalanche (chain 43113/43114): Backend mints FeTi70 tokens
	var mintHash string
	var tokenAmount float64
	var tokenName string

	// Check if contract-based minting or backend minting
	skipBackendMint := false

	// XDC (50/51): Always contract mints
	if chainID == 50 || chainID == 51 {
		log.Printf("🎯 [XDC Deposit] Contract handles minting automatically for XDC vault (chain %d)", chainID)
		skipBackendMint = true
	}

	// Redbelly (151/153): Check if LUCA contract by comparing contract address
	if chainID == 151 || chainID == 153 {
		lucaContractAddr := viper.GetString("vault.chains.redbelly_luca.contract_address")
		if strings.EqualFold(eventLog.Address.Hex(), lucaContractAddr) {
			log.Printf("🎯 [LUCA Deposit] Contract handles minting automatically for LUCA vault (chain %d, contract: %s)", chainID, eventLog.Address.Hex())
			skipBackendMint = true
		}
	}

	if skipBackendMint {
		// Contract-based minting - mint data will be extracted from contract events
		log.Printf("📝 [Contract Minting] Mint data will be extracted from blockchain events")
	} else {
		// Backend minting for Redbelly Ferrox & Avalanche
		log.Printf("🎯 [Backend Minting] Processing backend token transfer for chain %d...", chainID)
		log.Printf("📋 [Event Processing] Event details - Chain: %d, Contract: %s, User: %s, Position: %s, Amount: %s",
			chainID, eventLog.Address.Hex(), userAddress, positionId.String(), originalAmount.String())
		log.Printf("🔄 [Event Processing] Calling transferTokens function...")
		var err error
		mintHash, tokenAmount, tokenName, err = s.transferTokens(chainID, userAddress, originalAmount, eventLog.TxHash.Hex(), eventLog.Address.Hex())
		if err != nil {
			log.Printf("❌ Error transferring tokens: %v", err)
			// Log error to database
			s.errorService.LogEventError(
				chainID, userAddress, "VaultDeposit", models.EventStageTokenTransfer,
				models.ErrorTypeTransfer, fmt.Sprintf("Failed to transfer tokens: %v", err),
				txHash, int64(eventLog.BlockNumber), positionId.String(), models.SeverityCritical,
			)
			// Continue processing even if token transfer fails
		} else {
			log.Printf("✅ %s tokens minted successfully. Hash: %s, Amount: %.2f", tokenName, mintHash, tokenAmount)
		}
	}

	// Process event with vault service (creates VaultPosition document)
	if err := s.vaultService.ProcessVaultDepositEvent(&event); err != nil {
		log.Printf("Error processing VaultDeposit event: %v", err)
		// Log error to database
		s.errorService.LogEventError(
			chainID, userAddress, "VaultDeposit", models.EventStageProcessing,
			models.ErrorTypeProcessing, fmt.Sprintf("Failed to process VaultDeposit event: %v", err),
			txHash, int64(eventLog.BlockNumber), positionId.String(), models.SeverityHigh,
		)
	} else {
		log.Printf("Successfully processed VaultDeposit event for user %s, position %s, amount %s (status: %s)",
			userAddress, positionId.String(), originalAmount.String(), getStatusName(models.StatusActive))
	}

	// Update VaultPosition with transaction information (after document creation)
	if mintHash != "" && tokenAmount > 0 {
		log.Printf("🔄 [Event Processing] Updating VaultPosition with source chain and Redbelly transaction data...")
		s.updateVaultPositionWithMintHash(positionId.Uint64(), chainID, userAddress, eventLog.Address.Hex(), mintHash, tokenAmount, tokenName, eventLog.TxHash.Hex(), eventLog.BlockNumber)
	}
}

func (s *VaultBlockchainListener) processVaultRedeemedEvent(chainID int64, eventLog types.Log) {
	log.Printf("[VaultRedeemed] Block: %d, Tx: %s, Contract: %s",
		eventLog.BlockNumber, eventLog.TxHash.Hex(), eventLog.Address.Hex())

	// Extract indexed parameters first (needed for duplicate check)
	var userAddress string
	var positionId *big.Int
	if len(eventLog.Topics) >= 2 {
		// Normalize address to lowercase for consistency across all collections
		userAddress = strings.ToLower(common.HexToAddress(eventLog.Topics[1].Hex()).Hex())
	}
	if len(eventLog.Topics) >= 3 {
		positionId = new(big.Int).SetBytes(eventLog.Topics[2][:])
	}

	// Check if this event has already been processed (duplicate check)
	// IMPORTANT: Include both user AND position_id to handle multiple users with same position IDs
	txHash := eventLog.TxHash.Hex()
	var existingEvent models.VaultEvent
	err := repository.IRepo.FindOneWhere("vault_events", bson.M{
		"tx_hash":           txHash,
		"event_type":        "VaultRedeemed",
		"params.user":       userAddress,
		"params.positionId": positionId.String(),
	}, &existingEvent)
	if err == nil {
		log.Printf("⚠️ [VaultRedeemed] Skipping duplicate event with tx_hash: %s, user: %s, position: %s", txHash, userAddress, positionId.String())
		return
	}

	// Determine project based on contract address and chain ID
	project := getProjectFromContractAddress(eventLog.Address.Hex(), chainID)

	// Choose the correct ABI based on project
	var abiToUse string
	if project == "compute_labs" {
		abiToUse = computeLabsVaultABI
		log.Printf("🔍 [VaultRedeemed] Using Compute Labs ABI for project: %s", project)
	} else if project == "raze_reserve" {
		abiToUse = razeReserveVaultABI
		log.Printf("🔍 [VaultRedeemed] Using Raze Reserve ABI for project: %s", project)
	} else {
		abiToUse = vaultContractABI
		log.Printf("🔍 [VaultRedeemed] Using Ferrox ABI for project: %s", project)
	}

	// Parse non-indexed parameters using the appropriate ABI
	parsedABI, err := abi.JSON(strings.NewReader(abiToUse))
	if err != nil {
		log.Printf("Error parsing vault ABI: %v", err)
		return
	}

	// Define structures to match the event parameters exactly
	// Ferrox structure (with tier and redemptionTax)
	type FerroxVaultRedeemedEventData struct {
		PrincipalAmount *big.Int
		RewardsAmount   *big.Int
		TotalAmount     *big.Int
		RedemptionTax   *big.Int
		Tier            uint8
		VaultName       string
		VaultSymbol     string
		DepositTime     *big.Int
		LockEndTime     *big.Int
		RedeemTime      *big.Int
	}

	// Compute Labs structure (without tier, different field name)
	type ComputeLabsVaultRedeemedEventData struct {
		PrincipalAmount *big.Int
		YieldAmount     *big.Int // Compute Labs calls it yieldAmount instead of rewardsAmount
		TotalAmount     *big.Int
		RedemptionTax   *big.Int
		VaultName       string
		VaultSymbol     string
		DepositTime     *big.Int
		RedeemTime      *big.Int
	}

	// Raze Reserve structure (uses pendingReward, redemptionTax at the end)
	type RazeReserveVaultRedeemedEventData struct {
		PrincipalAmount *big.Int
		PendingReward   *big.Int
		TotalAmount     *big.Int
		Tier            uint8
		TierName        string
		TierSymbol      string
		DepositTime     *big.Int
		LockEndTime     *big.Int
		RedeemTime      *big.Int
		RedemptionTax   *big.Int
	}

	// Common fields to use regardless of structure
	var tier uint8
	var principalAmount, rewardsAmount, totalAmount, redemptionTax, depositTime, lockEndTime, redeemTime *big.Int
	var vaultName, vaultSymbol string

	if project == "compute_labs" {
		var eventData ComputeLabsVaultRedeemedEventData
		err = parsedABI.UnpackIntoInterface(&eventData, "VaultRedeemed", eventLog.Data)
		if err != nil {
			log.Printf("Error decoding Compute Labs VaultRedeemed event data: %v", err)
			return
		}
		// Map Compute Labs fields to common fields
		tier = 0 // Compute Labs doesn't have tiers
		principalAmount = eventData.PrincipalAmount
		rewardsAmount = eventData.YieldAmount // Note: Compute Labs uses yieldAmount
		totalAmount = eventData.TotalAmount
		redemptionTax = eventData.RedemptionTax
		vaultName = eventData.VaultName
		vaultSymbol = eventData.VaultSymbol
		depositTime = eventData.DepositTime
		lockEndTime = big.NewInt(0) // Compute Labs doesn't have lockEndTime in redeemed event
		redeemTime = eventData.RedeemTime
	} else if project == "raze_reserve" {
		var eventData RazeReserveVaultRedeemedEventData
		err = parsedABI.UnpackIntoInterface(&eventData, "VaultRedeemed", eventLog.Data)
		if err != nil {
			log.Printf("Error decoding Raze Reserve VaultRedeemed event data: %v", err)
			return
		}
		// Map Raze Reserve fields to common fields
		tier = eventData.Tier
		principalAmount = eventData.PrincipalAmount
		rewardsAmount = eventData.PendingReward
		totalAmount = eventData.TotalAmount
		redemptionTax = eventData.RedemptionTax
		vaultName = eventData.TierName
		vaultSymbol = eventData.TierSymbol
		depositTime = eventData.DepositTime
		lockEndTime = eventData.LockEndTime
		redeemTime = eventData.RedeemTime
	} else {
		var eventData FerroxVaultRedeemedEventData
		err = parsedABI.UnpackIntoInterface(&eventData, "VaultRedeemed", eventLog.Data)
		if err != nil {
			log.Printf("Error decoding Ferrox VaultRedeemed event data: %v", err)
			return
		}
		// Map Ferrox fields to common fields
		tier = eventData.Tier
		principalAmount = eventData.PrincipalAmount
		rewardsAmount = eventData.RewardsAmount
		totalAmount = eventData.TotalAmount
		redemptionTax = eventData.RedemptionTax
		vaultName = eventData.VaultName
		vaultSymbol = eventData.VaultSymbol
		depositTime = eventData.DepositTime
		lockEndTime = eventData.LockEndTime
		redeemTime = eventData.RedeemTime
	}

	// Determine user region based on contract address (US vs NON-US)
	userRegion := getUserRegionFromContract(eventLog.Address.Hex(), chainID, project)

	event := models.VaultEvent{
		ChainID:         chainID,
		Project:         project,
		BlockNumber:     int64(eventLog.BlockNumber),
		TxHash:          eventLog.TxHash.Hex(),
		EventType:       "VaultRedeemed",
		ContractAddress: eventLog.Address.Hex(),
		Params: map[string]interface{}{
			"user":            userAddress,
			"positionId":      positionId.String(),
			"principalAmount": principalAmount.String(),
			"rewardsAmount":   rewardsAmount.String(),
			"totalAmount":     totalAmount.String(),
			"redemptionTax":   redemptionTax.String(),
			"tier":            float64(tier),
			"vaultName":       vaultName,
			"vaultSymbol":     vaultSymbol,
			"depositTime":     depositTime.String(),
			"lockEndTime":     lockEndTime.String(),
			"redeemTime":      redeemTime.String(),
			"status":          float64(models.StatusCompleted), // NEW: Redeemed positions are COMPLETED
			"user_region":     userRegion,                      // ✅ FIXED: US vs NON-US differentiation for redemption events
		},
		CreatedAt: time.Now(),
	}

	if err := repository.IRepo.Create("vault_events", &event); err != nil {
		log.Printf("Error saving VaultRedeemed event: %v", err)
		return
	}

	if err := s.vaultService.ProcessVaultRedeemedEvent(&event); err != nil {
		log.Printf("Error processing VaultRedeemed event: %v", err)
	} else {
		log.Printf("Successfully processed VaultRedeemed event for user %s, position %s, total %s (status: %s)",
			userAddress, positionId.String(), totalAmount.String(), getStatusName(models.StatusCompleted))
	}
}

// processDistributionClaimedEvent handles DistributionClaimed events from Compute Labs vault
// Event signature: DistributionClaimed(address indexed user, uint256 indexed positionId, uint256 yieldAmount, uint256 taxAmount, uint256 claimTime)
func (s *VaultBlockchainListener) processDistributionClaimedEvent(chainID int64, eventLog types.Log) {
	log.Printf("[DistributionClaimed] Block: %d, Tx: %s, Contract: %s",
		eventLog.BlockNumber, eventLog.TxHash.Hex(), eventLog.Address.Hex())

	// Extract indexed parameters
	var userAddress string
	var positionId *big.Int
	if len(eventLog.Topics) >= 2 {
		userAddress = strings.ToLower(common.HexToAddress(eventLog.Topics[1].Hex()).Hex())
	}
	if len(eventLog.Topics) >= 3 {
		positionId = new(big.Int).SetBytes(eventLog.Topics[2][:])
	}

	// Check for duplicates
	txHash := eventLog.TxHash.Hex()
	var existingEvent models.ComputeLabsClaimEvent
	err := repository.IRepo.FindOneWhere("compute_labs_claim_events", bson.M{
		"tx_hash":      strings.ToLower(txHash),
		"user_address": userAddress,
		"position_id":  positionId.Uint64(),
		"chain_id":     chainID,
	}, &existingEvent)
	if err == nil {
		log.Printf("⚠️ [DistributionClaimed] Skipping duplicate event: tx=%s, user=%s, position=%s",
			txHash, userAddress, positionId.String())
		return
	}

	// Parse non-indexed parameters (yieldAmount, taxAmount, claimTime)
	parsedABI, err := abi.JSON(strings.NewReader(computeLabsVaultABI))
	if err != nil {
		log.Printf("Error parsing ABI: %v", err)
		return
	}

	type DistributionClaimedEventData struct {
		YieldAmount *big.Int // Must match ABI parameter name "yieldAmount"
		TaxAmount   *big.Int // Must match ABI parameter name "taxAmount"
		ClaimTime   *big.Int // Must match ABI parameter name "claimTime"
	}

	var eventData DistributionClaimedEventData
	err = parsedABI.UnpackIntoInterface(&eventData, "DistributionClaimed", eventLog.Data)
	if err != nil {
		log.Printf("Error decoding DistributionClaimed event: %v", err)
		return
	}

	// Convert yield amount and tax from base units (6 decimals for USDC)
	yieldAmountFloat, _ := s.vaultService.convertFromBaseUnits(eventData.YieldAmount.String(), 6)
	taxAmountFloat, _ := s.vaultService.convertFromBaseUnits(eventData.TaxAmount.String(), 6)

	// Extract claim period from timestamp (derive month from claim time)
	claimTime := time.Unix(eventData.ClaimTime.Int64(), 0)
	claimPeriod := int(claimTime.Month()) // Month number (1-12)

	// Create ComputeLabsClaimEvent record
	claimEvent := models.ComputeLabsClaimEvent{
		ID:              primitive.NewObjectID(),
		ChainID:         chainID,
		ContractAddress: strings.ToLower(eventLog.Address.Hex()),
		TxHash:          strings.ToLower(txHash),
		BlockNumber:     eventLog.BlockNumber,
		EventIndex:      uint(eventLog.Index),
		UserAddress:     userAddress,
		PositionID:      positionId.Uint64(),
		RewardAmount:    yieldAmountFloat,
		RewardAmountRaw: eventData.YieldAmount.String(),
		TaxAmount:       taxAmountFloat,
		TaxAmountRaw:    eventData.TaxAmount.String(),
		ClaimPeriod:     claimPeriod,
		Processed:       false,
		CreatedAt:       time.Now(),
	}

	// Save event to database
	err = repository.IRepo.Insert("compute_labs_claim_events", &claimEvent)
	if err != nil {
		log.Printf("Error saving DistributionClaimed event: %v", err)
		return
	}

	log.Printf("✅ [DistributionClaimed] Saved event: user=%s, position=%d, amount=%.2f USDC, tax=%.2f USDC, claim_time=%s",
		userAddress, positionId.Uint64(), yieldAmountFloat, taxAmountFloat, claimTime.Format("2006-01-02 15:04:05"))

	// Process the claim event immediately (updates vault_positions, creates claim record)
	computeLabsService := NewComputeLabsService()
	if err := computeLabsService.ProcessClaimEvent(&claimEvent); err != nil {
		log.Printf("Error processing DistributionClaimed event: %v", err)
	} else {
		log.Printf("✅ Successfully processed DistributionClaimed event for user %s, position %d, amount %.2f USDC",
			userAddress, positionId.Uint64(), yieldAmountFloat)
	}
}

// processDistributionScheduleInitiatedEvent handles DistributionScheduleInitiated events from Compute Labs vault
// Event signature: DistributionScheduleInitiated(address indexed admin, uint256 firstDistributionDate, uint256 timestamp)
func (s *VaultBlockchainListener) processDistributionScheduleInitiatedEvent(chainID int64, eventLog types.Log) {
	log.Printf("[DistributionScheduleInitiated] Block: %d, Tx: %s, Contract: %s",
		eventLog.BlockNumber, eventLog.TxHash.Hex(), eventLog.Address.Hex())

	// Extract indexed parameter (admin)
	var adminAddress string
	if len(eventLog.Topics) >= 2 {
		adminAddress = strings.ToLower(common.HexToAddress(eventLog.Topics[1].Hex()).Hex())
	}

	// Check for duplicates
	txHash := eventLog.TxHash.Hex()
	var existingEvent bson.M
	err := repository.IRepo.FindOneWhere("compute_labs_distribution_events", bson.M{
		"tx_hash":  strings.ToLower(txHash),
		"chain_id": chainID,
	}, &existingEvent)
	if err == nil {
		log.Printf("⚠️ [DistributionScheduleInitiated] Skipping duplicate event: tx=%s", txHash)
		return
	}

	// Parse non-indexed parameters (firstDistributionDate, timestamp)
	parsedABI, err := abi.JSON(strings.NewReader(computeLabsVaultABI))
	if err != nil {
		log.Printf("Error parsing ABI: %v", err)
		return
	}

	type DistributionScheduleInitiatedEventData struct {
		FirstDistributionDate *big.Int
		Timestamp             *big.Int
	}

	var eventData DistributionScheduleInitiatedEventData
	err = parsedABI.UnpackIntoInterface(&eventData, "DistributionScheduleInitiated", eventLog.Data)
	if err != nil {
		log.Printf("Error decoding DistributionScheduleInitiated event: %v", err)
		return
	}

	// Convert timestamps to time.Time
	firstDistributionDate := time.Unix(eventData.FirstDistributionDate.Int64(), 0)
	eventTimestamp := time.Unix(eventData.Timestamp.Int64(), 0)

	log.Printf("✅ [DistributionScheduleInitiated] Admin=%s, FirstDistribution=%s, EventTime=%s",
		adminAddress, firstDistributionDate.Format("2006-01-02"), eventTimestamp.Format("2006-01-02 15:04:05"))

	// Auto-create claim periods starting from firstDistributionDate
	computeLabsService := NewComputeLabsService()
	if err := computeLabsService.InitializeDistributionSchedule(firstDistributionDate); err != nil {
		log.Printf("❌ Error initializing distribution schedule: %v", err)
	} else {
		log.Printf("✅ Successfully initialized distribution schedule from %s", firstDistributionDate.Format("2006-01-02"))
	}
}

// processBuyoutScheduledEvent handles BuyoutScheduled events from Compute Labs vault
// Event signature: BuyoutScheduled(address indexed admin, uint256 buyoutDate, uint256 timestamp)
func (s *VaultBlockchainListener) processBuyoutScheduledEvent(chainID int64, eventLog types.Log) {
	log.Printf("[BuyoutScheduled] Block: %d, Tx: %s, Contract: %s",
		eventLog.BlockNumber, eventLog.TxHash.Hex(), eventLog.Address.Hex())

	// Extract indexed parameter (admin)
	var adminAddress string
	if len(eventLog.Topics) >= 2 {
		adminAddress = strings.ToLower(common.HexToAddress(eventLog.Topics[1].Hex()).Hex())
	}

	// Check for duplicates
	txHash := eventLog.TxHash.Hex()
	var existingSchedule models.ComputeLabsBuyoutSchedule
	err := repository.IRepo.FindOneWhere(models.ComputeLabsBuyoutScheduleCollection, bson.M{
		"tx_hash":  strings.ToLower(txHash),
		"chain_id": chainID,
	}, &existingSchedule)
	if err == nil {
		log.Printf("⚠️ [BuyoutScheduled] Skipping duplicate event: tx=%s", txHash)
		return
	}

	// Parse non-indexed parameters (buyoutDate, timestamp)
	parsedABI, err := abi.JSON(strings.NewReader(computeLabsVaultABI))
	if err != nil {
		log.Printf("Error parsing ABI: %v", err)
		return
	}

	type BuyoutScheduledEventData struct {
		BuyoutDate *big.Int
		Timestamp  *big.Int
	}

	var eventData BuyoutScheduledEventData
	err = parsedABI.UnpackIntoInterface(&eventData, "BuyoutScheduled", eventLog.Data)
	if err != nil {
		log.Printf("Error decoding BuyoutScheduled event: %v", err)
		return
	}

	// Convert timestamps to time.Time
	buyoutDate := time.Unix(eventData.BuyoutDate.Int64(), 0)
	eventTimestamp := time.Unix(eventData.Timestamp.Int64(), 0)

	// ============================================================
	// Calculate funding needed (before creating any records)
	// ============================================================

	// Get all active positions to calculate funding needed
	var positions []models.VaultPosition
	err = repository.IRepo.FindWhere("vault_positions", bson.M{
		"project": "compute_labs",
		"status":  models.StatusActive,
	}, &positions)

	totalOriginalInvestment := 0.0
	totalUnclaimedRewards := 0.0
	totalAlreadyClaimed := 0.0

	if err == nil && len(positions) > 0 {
		// Calculate total amounts needed
		for _, pos := range positions {
			totalOriginalInvestment += pos.OriginalInvestmentAmount

			// Calculate TOTAL rewards from deposit until buyout date
			// Use seconds-based calculation (matches CalculateRewardsUntilDate and calculateDisplayRewards)
			depositTime := pos.DepositTime
			if buyoutDate.Before(depositTime) {
				continue
			}

			// Use precise seconds-based calculation for accurate rewards
			secondsActive := buyoutDate.Sub(depositTime).Seconds()
			if secondsActive < 0 {
				continue
			}

			// Formula: (investment × rate × seconds) / (secondsPerYear × BASIS_POINTS)
			const BASIS_POINTS = 10000
			const SECONDS_PER_DAY = 86400
			secondsPerYear := float64(365 * SECONDS_PER_DAY)

			totalRewards := (pos.OriginalInvestmentAmount * float64(pos.ARRRate) * secondsActive) / (secondsPerYear * float64(BASIS_POINTS))

			// IMPORTANT: Subtract already claimed rewards!
			// Users already received claimed rewards via claimDistribution()
			// At buyout, they only get UNCLAIMED portion
			unclaimedRewards := totalRewards - pos.TotalRewardsClaimed
			if unclaimedRewards < 0 {
				unclaimedRewards = 0 // Safety check
			}

			totalUnclaimedRewards += unclaimedRewards
			totalAlreadyClaimed += pos.TotalRewardsClaimed
		}

		log.Printf("💰 [BuyoutScheduled] Funding calculation:")
		log.Printf("   Positions: %d", len(positions))
		log.Printf("   Original Investment (what users get back): $%.2f", totalOriginalInvestment)
		log.Printf("   Total Rewards (deposit → buyout): $%.2f", totalUnclaimedRewards+totalAlreadyClaimed)
		log.Printf("   Already Claimed by Users: $%.2f", totalAlreadyClaimed)
		log.Printf("   Unclaimed Rewards (need funding): $%.2f", totalUnclaimedRewards)
		log.Printf("   Total Funding Needed: $%.2f (investment + unclaimed)", totalOriginalInvestment+totalUnclaimedRewards)
	} else {
		log.Printf("⚠️ [BuyoutScheduled] No active positions found, setting amounts to 0")
	}

	fundingAmount := totalOriginalInvestment + totalUnclaimedRewards

	// Create buyout record for the vault API
	buyout := &models.ComputeLabsBuyout{
		ID:                     primitive.NewObjectID(),
		BuyoutDate:             buyoutDate,
		ScheduledBy:            adminAddress,
		ScheduledAt:            eventTimestamp,
		FundingAmount:          fundingAmount,
		FundingConfirmed:       false,
		Status:                 models.BuyoutStatusScheduled,
		IsActive:               false,
		TotalPositionsAffected: len(positions),
		TotalPrincipalAmount:   totalOriginalInvestment,
		TotalAccruedRewards:    totalUnclaimedRewards, // Only unclaimed rewards need funding
		PositionsRedeemed:      0,
		PrincipalRedeemed:      0,
		RewardsRedeemed:        0,
		IsIrreversible:         true,
		Notes:                  fmt.Sprintf("Scheduled via blockchain event. Tx: %s", strings.ToLower(txHash)),
		CreatedAt:              time.Now(),
		UpdatedAt:              time.Now(),
	}

	err = repository.IRepo.Insert("compute_labs_buyouts", buyout)
	if err != nil {
		log.Printf("❌ [BuyoutScheduled] Error creating buyout record in compute_labs_buyouts: %v", err)
		return
	}

	log.Printf("✅ [BuyoutScheduled] Created buyout record in compute_labs_buyouts: ID=%s, BuyoutDate=%s, FundingAmount=$%.2f",
		buyout.ID.Hex(), buyoutDate.Format("2006-01-02"), fundingAmount)

	// ALSO create record in compute_labs_buyout_schedules for API compatibility
	buyoutSchedule := &models.ComputeLabsBuyoutSchedule{
		ID:                      primitive.NewObjectID(),
		ChainID:                 chainID,
		ContractAddress:         strings.ToLower(eventLog.Address.Hex()),
		TxHash:                  strings.ToLower(txHash),
		BlockNumber:             eventLog.BlockNumber,
		AdminAddress:            adminAddress,
		BuyoutDate:              buyoutDate,
		EventTimestamp:          eventTimestamp,
		Status:                  "scheduled",
		FundingAmount:           fundingAmount,
		TotalOriginalInvestment: totalOriginalInvestment,
		TotalAccruedRewards:     totalUnclaimedRewards,
		TotalPositionsAffected:  len(positions),
		CreatedAt:               time.Now(),
	}

	err = repository.IRepo.Insert(models.ComputeLabsBuyoutScheduleCollection, buyoutSchedule)
	if err != nil {
		log.Printf("❌ [BuyoutScheduled] Error creating schedule record in %s: %v", models.ComputeLabsBuyoutScheduleCollection, err)
		return
	}

	log.Printf("✅ [BuyoutScheduled] Created buyout schedule record: ID=%s, BuyoutDate=%s",
		buyoutSchedule.ID.Hex(), buyoutDate.Format("2006-01-02"))
}

// processBuyoutExecutedEvent handles BuyoutExecuted events from Compute Labs vault
// Event signature: BuyoutExecuted(address indexed admin, uint256 totalPositionsAffected, uint256 timestamp)
func (s *VaultBlockchainListener) processBuyoutExecutedEvent(chainID int64, eventLog types.Log) {
	log.Printf("[BuyoutExecuted] Block: %d, Tx: %s, Contract: %s",
		eventLog.BlockNumber, eventLog.TxHash.Hex(), eventLog.Address.Hex())

	// Extract indexed parameter (admin)
	var adminAddress string
	if len(eventLog.Topics) >= 2 {
		adminAddress = strings.ToLower(common.HexToAddress(eventLog.Topics[1].Hex()).Hex())
	}

	// Check for duplicates
	txHash := eventLog.TxHash.Hex()
	var existingExecution bson.M
	err := repository.IRepo.FindOneWhere("compute_labs_buyout_executions", bson.M{
		"tx_hash":  strings.ToLower(txHash),
		"chain_id": chainID,
	}, &existingExecution)
	if err == nil {
		log.Printf("⚠️ [BuyoutExecuted] Skipping duplicate event: tx=%s", txHash)
		return
	}

	// Parse non-indexed parameters (totalPositionsAffected, timestamp)
	parsedABI, err := abi.JSON(strings.NewReader(computeLabsVaultABI))
	if err != nil {
		log.Printf("Error parsing ABI: %v", err)
		return
	}

	type BuyoutExecutedEventData struct {
		TotalPositionsAffected *big.Int
		Timestamp              *big.Int
	}

	var eventData BuyoutExecutedEventData
	err = parsedABI.UnpackIntoInterface(&eventData, "BuyoutExecuted", eventLog.Data)
	if err != nil {
		log.Printf("Error decoding BuyoutExecuted event: %v", err)
		return
	}

	// Convert timestamp to time.Time
	eventTimestamp := time.Unix(eventData.Timestamp.Int64(), 0)
	totalPositions := eventData.TotalPositionsAffected.Uint64()

	log.Printf("✅ [BuyoutExecuted] Admin=%s, PositionsAffected=%d, EventTime=%s",
		adminAddress, totalPositions, eventTimestamp.Format("2006-01-02 15:04:05"))

	// Update buyout schedule status to "executed"
	computeLabsService := NewComputeLabsService()
	if err := computeLabsService.MarkBuyoutAsExecuted(chainID, eventTimestamp); err != nil {
		log.Printf("❌ Error marking buyout as executed: %v", err)
	} else {
		log.Printf("✅ Successfully marked buyout as executed, %d positions affected", totalPositions)
	}
}

// processCLGPUTokensTransferredEvent handles CLGPUTokensTransferred events from Compute Labs vault
// Event signature: CLGPUTokensTransferred(address indexed from, address indexed to, uint256 indexed positionId, uint256 amount, uint256 timestamp)
// This event is emitted when CLGPU tokens are minted on deposit (similar to XTFTokensTransferred for Ferrox US)
func (s *VaultBlockchainListener) processCLGPUTokensTransferredEvent(chainID int64, eventLog types.Log) {
	log.Printf("[CLGPUTokensTransferred] Block: %d, Tx: %s, Contract: %s",
		eventLog.BlockNumber, eventLog.TxHash.Hex(), eventLog.Address.Hex())

	// Extract indexed parameters (from, to, positionId)
	var toAddress string
	var positionId *big.Int
	// Skip Topics[0] (event signature) and Topics[1] (from address)
	if len(eventLog.Topics) >= 3 {
		toAddress = strings.ToLower(common.HexToAddress(eventLog.Topics[2].Hex()).Hex())
	}
	if len(eventLog.Topics) >= 4 {
		positionId = new(big.Int).SetBytes(eventLog.Topics[3][:])
	}

	// Parse non-indexed parameters (amount, timestamp)
	parsedABI, err := abi.JSON(strings.NewReader(computeLabsVaultABI))
	if err != nil {
		log.Printf("Error parsing vault ABI: %v", err)
		return
	}

	type CLGPUTokensTransferredEventData struct {
		Amount    *big.Int
		Timestamp *big.Int
	}

	var eventData CLGPUTokensTransferredEventData
	err = parsedABI.UnpackIntoInterface(&eventData, "CLGPUTokensTransferred", eventLog.Data)
	if err != nil {
		log.Printf("Error decoding CLGPUTokensTransferred event data: %v", err)
		return
	}

	// Convert amount from base units (6 decimals for USDC/CLGPU tokens)
	tokenAmountFloat, err := convertFromBaseUnits(eventData.Amount.String(), USDT_DECIMALS)
	if err != nil {
		log.Printf("Error converting token amount: %v", err)
		return
	}

	// Token name for Compute Labs
	tokenName := "CLGPU"

	log.Printf("📋 [CLGPUTokensTransferred] Position %s: %.2f %s tokens minted to %s (tx: %s)",
		positionId.String(), tokenAmountFloat, tokenName, toAddress, eventLog.TxHash.Hex())

	// Update VaultPosition with mint information
	// Note: user_address uses lowercase (stored lowercase in DB)
	// contract_address uses case-insensitive regex to match old records with mixed case
	filter := bson.M{
		"user_address": toAddress,
		"chain_id":     chainID,
		"contract_address": bson.M{
			"$regex":   "^" + strings.ToLower(eventLog.Address.Hex()) + "$",
			"$options": "i", // case-insensitive
		},
		"position_id": positionId.Uint64(),
		"project":     "compute_labs", // Ensure we only update Compute Labs positions
	}

	mintTime := time.Now()
	update := bson.M{
		"$set": bson.M{
			"mint_hash":         eventLog.TxHash.Hex(),
			"mint_tx_status":    "confirmed",
			"mint_tx_time":      mintTime,
			"mint_token_amount": tokenAmountFloat,
			"mint_token_name":   tokenName, // CLGPU token
			"updated_at":        time.Now(),
		},
	}

	err = repository.IRepo.UpdateOne("vault_positions", filter, update, false)
	if err != nil {
		log.Printf("❌ Error updating VaultPosition with CLGPU mint data: %v", err)
	} else {
		log.Printf("✅ Updated Compute Labs VaultPosition %s with CLGPU mint data: hash=%s, amount=%.2f %s",
			positionId.String(), eventLog.TxHash.Hex(), tokenAmountFloat, tokenName)
	}

	// IMPORTANT: If buyout is scheduled (but not executed), update the funding amount
	// to include this new deposit that came after scheduling
	var buyoutSchedule models.ComputeLabsBuyoutSchedule
	err = repository.IRepo.FindOneWhere(models.ComputeLabsBuyoutScheduleCollection, bson.M{
		"status": "scheduled", // Buyout scheduled but not executed yet
	}, &buyoutSchedule)

	if err == nil {
		// Buyout is scheduled - we need to update funding to include this new deposit
		log.Printf("🔄 [CLGPUTokensTransferred] Buyout is scheduled, updating funding for new deposit...")

		// Get the position to calculate rewards
		var position models.VaultPosition
		err = repository.IRepo.FindOneWhere("vault_positions", filter, &position)
		if err != nil {
			log.Printf("⚠️ Could not find position to update funding: %v", err)
			return
		}

		// Calculate rewards from deposit until buyout date
		depositTime := position.DepositTime
		buyoutDate := buyoutSchedule.BuyoutDate

		if buyoutDate.Before(depositTime) {
			log.Printf("⚠️ Buyout date is before deposit time, no funding update needed")
			return
		}

		secondsActive := buyoutDate.Sub(depositTime).Seconds()
		if secondsActive < 0 {
			secondsActive = 0
		}

		// Formula: (investment × rate × seconds) / (secondsPerYear × BASIS_POINTS)
		const BASIS_POINTS = 10000
		const SECONDS_PER_DAY = 86400
		secondsPerYear := float64(365 * SECONDS_PER_DAY)

		totalRewards := (position.OriginalInvestmentAmount * float64(position.ARRRate) * secondsActive) / (secondsPerYear * float64(BASIS_POINTS))

		// Subtract already claimed (should be 0 for new deposits)
		unclaimedRewards := totalRewards - position.TotalRewardsClaimed
		if unclaimedRewards < 0 {
			unclaimedRewards = 0
		}

		// Calculate additional funding needed for this position
		additionalFunding := position.OriginalInvestmentAmount + unclaimedRewards

		log.Printf("💰 [CLGPUTokensTransferred] New deposit after buyout scheduled:")
		log.Printf("   Original Investment: $%.2f", position.OriginalInvestmentAmount)
		log.Printf("   Rewards (deposit → buyout): $%.2f", totalRewards)
		log.Printf("   Already Claimed: $%.2f", position.TotalRewardsClaimed)
		log.Printf("   Additional Funding Needed: $%.2f", additionalFunding)

		// Update funding amount in compute_labs_buyout_schedules
		err = repository.IRepo.UpdateOne(models.ComputeLabsBuyoutScheduleCollection, bson.M{
			"_id": buyoutSchedule.ID,
		}, bson.M{
			"$inc": bson.M{
				"funding_amount": additionalFunding,
			},
		}, false)

		if err != nil {
			log.Printf("❌ Failed to update buyout schedule funding: %v", err)
		} else {
			log.Printf("✅ Updated buyout schedule funding: added $%.2f (new total: $%.2f)",
				additionalFunding, buyoutSchedule.FundingAmount+additionalFunding)
		}

		// Also update compute_labs_buyouts collection
		err = repository.IRepo.UpdateOne("compute_labs_buyouts", bson.M{
			"buyout_date": buyoutSchedule.BuyoutDate,
			"status":      "scheduled",
		}, bson.M{
			"$inc": bson.M{
				"funding_amount":           additionalFunding,
				"total_positions_affected": 1,
				"total_principal_amount":   position.OriginalInvestmentAmount,
				"total_accrued_rewards":    unclaimedRewards,
			},
		}, false)

		if err != nil {
			log.Printf("⚠️ Failed to update compute_labs_buyouts funding: %v (non-critical)", err)
		} else {
			log.Printf("✅ Updated compute_labs_buyouts funding as well")
		}
	}
}

func (s *VaultBlockchainListener) processRedemptionRequestedEvent(chainID int64, eventLog types.Log) {
	log.Printf("[RedemptionRequested] Block: %d, Tx: %s, Contract: %s",
		eventLog.BlockNumber, eventLog.TxHash.Hex(), eventLog.Address.Hex())

	// Extract indexed parameters first (needed for duplicate check)
	var userAddress string
	var positionId *big.Int
	if len(eventLog.Topics) >= 2 {
		// Normalize address to lowercase for consistency across all collections
		userAddress = strings.ToLower(common.HexToAddress(eventLog.Topics[1].Hex()).Hex())
	}
	if len(eventLog.Topics) >= 3 {
		positionId = new(big.Int).SetBytes(eventLog.Topics[2][:])
	}

	// Check if this event has already been processed (duplicate check)
	// IMPORTANT: Include both user AND position_id to handle multiple users with same position IDs
	txHash := eventLog.TxHash.Hex()
	var existingEvent models.VaultEvent
	err := repository.IRepo.FindOneWhere("vault_events", bson.M{
		"tx_hash":           txHash,
		"event_type":        "RedemptionRequested",
		"params.user":       userAddress,
		"params.positionId": positionId.String(),
	}, &existingEvent)
	if err == nil {
		log.Printf("⚠️ [RedemptionRequested] Skipping duplicate event with tx_hash: %s, user: %s, position: %s", txHash, userAddress, positionId.String())
		return
	}

	// Parse non-indexed parameters using COMPLETE ABI
	parsedABI, err := abi.JSON(strings.NewReader(vaultContractABI))
	if err != nil {
		log.Printf("Error parsing vault ABI: %v", err)
		return
	}

	// FIXED: Structure matches contract event order exactly
	type RedemptionRequestedEventData struct {
		AvailableTime  *big.Int
		RequestTime    *big.Int
		Tier           uint8
		OriginalAmount *big.Int
		CurrentValue   *big.Int
	}

	var eventData RedemptionRequestedEventData
	err = parsedABI.UnpackIntoInterface(&eventData, "RedemptionRequested", eventLog.Data)
	if err != nil {
		log.Printf("Error decoding RedemptionRequested event data: %v", err)
		return
	}

	// Determine the status based on available time
	var status uint8
	currentTime := time.Now().Unix()
	if eventData.AvailableTime.Int64() <= currentTime {
		status = models.StatusAvailable
	} else {
		status = models.StatusPending
	}

	// Determine project based on contract address and chain ID
	project := getProjectFromContractAddress(eventLog.Address.Hex(), chainID)

	// Determine user region based on contract address (US vs NON-US)
	userRegion := getUserRegionFromContract(eventLog.Address.Hex(), chainID, project)

	event := models.VaultEvent{
		ChainID:         chainID,
		Project:         project,
		BlockNumber:     int64(eventLog.BlockNumber),
		TxHash:          eventLog.TxHash.Hex(),
		EventType:       "RedemptionRequested",
		ContractAddress: eventLog.Address.Hex(),
		Params: map[string]interface{}{
			"user":           userAddress,
			"positionId":     positionId.String(),
			"availableTime":  eventData.AvailableTime.String(),
			"requestTime":    eventData.RequestTime.String(),
			"tier":           float64(eventData.Tier),
			"originalAmount": eventData.OriginalAmount.String(),
			"currentValue":   eventData.CurrentValue.String(),
			"status":         float64(status), // NEW: Add calculated status
			"user_region":    userRegion,      // ✅ FIXED: US vs NON-US differentiation for redemption request events
		},
		CreatedAt: time.Now(),
	}

	if err := repository.IRepo.Create("vault_events", &event); err != nil {
		log.Printf("Error saving RedemptionRequested event: %v", err)
		return
	}

	if err := s.vaultService.ProcessRedemptionRequestedEvent(&event); err != nil {
		log.Printf("Error processing RedemptionRequested event: %v", err)
	} else {
		log.Printf("Successfully processed RedemptionRequested event for user %s, position %s (status: %s)",
			userAddress, positionId.String(), getStatusName(status))
	}
}

// UPDATED: Renamed and updated function for single status system
func (s *VaultBlockchainListener) processPositionStatusUpdatedEvent(chainID int64, eventLog types.Log) {
	log.Printf("[PositionStatusUpdated] Block: %d, Tx: %s, Contract: %s",
		eventLog.BlockNumber, eventLog.TxHash.Hex(), eventLog.Address.Hex())

	// Extract indexed parameters first (needed for duplicate check)
	var userAddress string
	var positionId *big.Int
	if len(eventLog.Topics) >= 2 {
		// Normalize address to lowercase for consistency across all collections
		userAddress = strings.ToLower(common.HexToAddress(eventLog.Topics[1].Hex()).Hex())
	}
	if len(eventLog.Topics) >= 3 {
		positionId = new(big.Int).SetBytes(eventLog.Topics[2][:])
	}

	// Check if this event has already been processed (duplicate check)
	// IMPORTANT: Include both user AND position_id to handle multiple users with same position IDs
	txHash := eventLog.TxHash.Hex()
	var existingEvent models.VaultEvent
	err := repository.IRepo.FindOneWhere("vault_events", bson.M{
		"tx_hash":           txHash,
		"event_type":        "PositionStatusUpdated",
		"params.user":       userAddress,
		"params.positionId": positionId.String(),
	}, &existingEvent)
	if err == nil {
		log.Printf("⚠️ [PositionStatusUpdated] Skipping duplicate event with tx_hash: %s, user: %s, position: %s", txHash, userAddress, positionId.String())
		return
	}

	// Parse non-indexed parameters using COMPLETE ABI
	parsedABI, err := abi.JSON(strings.NewReader(vaultContractABI))
	if err != nil {
		log.Printf("Error parsing vault ABI: %v", err)
		return
	}

	// UPDATED: Structure matches new contract event order exactly
	type PositionStatusUpdatedEventData struct {
		OldStatus  uint8 // NEW: Added old status
		NewStatus  uint8 // Updated field name
		UpdateTime *big.Int
	}

	var eventData PositionStatusUpdatedEventData
	err = parsedABI.UnpackIntoInterface(&eventData, "PositionStatusUpdated", eventLog.Data)
	if err != nil {
		log.Printf("Error decoding PositionStatusUpdated event data: %v", err)
		return
	}

	event := models.VaultEvent{
		ChainID:         chainID,
		Project:         getProjectFromContractAddress(eventLog.Address.Hex(), chainID),
		BlockNumber:     int64(eventLog.BlockNumber),
		TxHash:          eventLog.TxHash.Hex(),
		EventType:       "PositionStatusUpdated", // UPDATED: Changed event type name
		ContractAddress: eventLog.Address.Hex(),
		Params: map[string]interface{}{
			"user":       userAddress,
			"positionId": positionId.String(),
			"oldStatus":  float64(eventData.OldStatus), // NEW: Added old status
			"newStatus":  float64(eventData.NewStatus), // Updated field name
			"updateTime": eventData.UpdateTime.String(),
		},
		CreatedAt: time.Now(),
	}

	if err := repository.IRepo.Create("vault_events", &event); err != nil {
		log.Printf("Error saving PositionStatusUpdated event: %v", err)
		return
	}

	// UPDATED: Use new service method name
	if err := s.vaultService.ProcessPositionStatusUpdatedEvent(&event); err != nil {
		log.Printf("Error processing PositionStatusUpdated event: %v", err)
	} else {
		log.Printf("Successfully processed PositionStatusUpdated event for user %s, position %s, status change: %s → %s",
			userAddress, positionId.String(), getStatusName(eventData.OldStatus), getStatusName(eventData.NewStatus))
	}
}

func (s *VaultBlockchainListener) processVaultRolledOverEvent(chainID int64, eventLog types.Log) {
	log.Printf("[VaultRolledOver] Block: %d, Tx: %s, Contract: %s",
		eventLog.BlockNumber, eventLog.TxHash.Hex(), eventLog.Address.Hex())

	// Extract indexed parameters first (needed for duplicate check)
	var userAddress string
	var positionId *big.Int
	if len(eventLog.Topics) >= 2 {
		// Normalize address to lowercase for consistency across all collections
		userAddress = strings.ToLower(common.HexToAddress(eventLog.Topics[1].Hex()).Hex())
	}
	if len(eventLog.Topics) >= 3 {
		positionId = new(big.Int).SetBytes(eventLog.Topics[2][:])
	}

	// Check if this event has already been processed (duplicate check)
	// IMPORTANT: Include both user AND position_id to handle multiple users with same position IDs
	txHash := eventLog.TxHash.Hex()
	var existingEvent models.VaultEvent
	err := repository.IRepo.FindOneWhere("vault_events", bson.M{
		"tx_hash":           txHash,
		"event_type":        "VaultRolledOver",
		"params.user":       userAddress,
		"params.positionId": positionId.String(),
	}, &existingEvent)
	if err == nil {
		log.Printf("⚠️ [VaultRolledOver] Skipping duplicate event with tx_hash: %s, user: %s, position: %s", txHash, userAddress, positionId.String())
		return
	}

	// Determine project based on contract address and chain ID
	project := getProjectFromContractAddress(eventLog.Address.Hex(), chainID)

	// 129knots does not support rollover - skip processing
	if project == "129knots" {
		log.Printf("⏭️ [VaultRolledOver] Skipping VaultRolledOver event for 129knots (no rollover support)")
		return
	}

	// Parse non-indexed parameters using COMPLETE ABI
	parsedABI, err := abi.JSON(strings.NewReader(vaultContractABI))
	if err != nil {
		log.Printf("Error parsing vault ABI: %v", err)
		return
	}

	type VaultRolledOverEventData struct {
		NewLockEndTime *big.Int
		RolloverTime   *big.Int
		Tier           uint8
	}

	var eventData VaultRolledOverEventData
	err = parsedABI.UnpackIntoInterface(&eventData, "VaultRolledOver", eventLog.Data)
	if err != nil {
		log.Printf("Error decoding VaultRolledOver event data: %v", err)
		return
	}

	// Determine user region based on contract address (US vs NON-US)
	userRegion := getUserRegionFromContract(eventLog.Address.Hex(), chainID, project)

	event := models.VaultEvent{
		ChainID:         chainID,
		Project:         project,
		BlockNumber:     int64(eventLog.BlockNumber),
		TxHash:          eventLog.TxHash.Hex(),
		EventType:       "VaultRolledOver",
		ContractAddress: eventLog.Address.Hex(),
		Params: map[string]interface{}{
			"user":           userAddress,
			"positionId":     positionId.String(),
			"newLockEndTime": eventData.NewLockEndTime.String(),
			"rolloverTime":   eventData.RolloverTime.String(),
			"tier":           float64(eventData.Tier),
			"status":         float64(models.StatusActive),
			"user_region":    userRegion,
		},
		CreatedAt: time.Now(),
	}

	if err := repository.IRepo.Create("vault_events", &event); err != nil {
		log.Printf("Error saving VaultRolledOver event: %v", err)
		return
	}

	if err := s.vaultService.ProcessVaultRolledOverEvent(&event); err != nil {
		log.Printf("Error processing VaultRolledOver event: %v", err)
	} else {
		log.Printf("Successfully processed VaultRolledOver event for user %s, position %s (status: %s)",
			userAddress, positionId.String(), getStatusName(models.StatusActive))
	}
}

// processClaimRequestedEvent handles ClaimRequested events from Raze Reserve vault
// This is emitted when the investor clicks "Redeem Now" → status changes to ClaimRequested (4)
func (s *VaultBlockchainListener) processClaimRequestedEvent(chainID int64, eventLog types.Log) {
	log.Printf("[ClaimRequested] Block: %d, Tx: %s, Contract: %s",
		eventLog.BlockNumber, eventLog.TxHash.Hex(), eventLog.Address.Hex())

	// Extract indexed parameters
	var userAddress string
	var positionId *big.Int
	if len(eventLog.Topics) >= 2 {
		userAddress = strings.ToLower(common.HexToAddress(eventLog.Topics[1].Hex()).Hex())
	}
	if len(eventLog.Topics) >= 3 {
		positionId = new(big.Int).SetBytes(eventLog.Topics[2][:])
	}

	// Duplicate check
	txHash := eventLog.TxHash.Hex()
	var existingEvent models.VaultEvent
	err := repository.IRepo.FindOneWhere("vault_events", bson.M{
		"tx_hash":           txHash,
		"event_type":        "ClaimRequested",
		"params.user":       userAddress,
		"params.positionId": positionId.String(),
	}, &existingEvent)
	if err == nil {
		log.Printf("[ClaimRequested] Skipping duplicate event: tx=%s, user=%s, position=%s", txHash, userAddress, positionId.String())
		return
	}

	// Parse non-indexed parameters
	parsedABI, err := abi.JSON(strings.NewReader(razeReserveVaultABI))
	if err != nil {
		log.Printf("Error parsing Raze Reserve ABI: %v", err)
		return
	}

	type ClaimRequestedEventData struct {
		PrincipalAmount *big.Int
		PendingReward   *big.Int
		TotalAmount     *big.Int
		Tier            uint8
		TierName        string
		TierSymbol      string
		DepositTime     *big.Int
		LockEndTime     *big.Int
		RedeemTime      *big.Int
	}

	var eventData ClaimRequestedEventData
	err = parsedABI.UnpackIntoInterface(&eventData, "ClaimRequested", eventLog.Data)
	if err != nil {
		log.Printf("Error decoding ClaimRequested event data: %v", err)
		return
	}

	project := getProjectFromContractAddress(eventLog.Address.Hex(), chainID)
	userRegion := getUserRegionFromContract(eventLog.Address.Hex(), chainID, project)

	event := models.VaultEvent{
		ChainID:         chainID,
		Project:         project,
		BlockNumber:     int64(eventLog.BlockNumber),
		TxHash:          eventLog.TxHash.Hex(),
		EventType:       "ClaimRequested",
		ContractAddress: eventLog.Address.Hex(),
		Params: map[string]interface{}{
			"user":            userAddress,
			"positionId":      positionId.String(),
			"principalAmount": eventData.PrincipalAmount.String(),
			"pendingReward":   eventData.PendingReward.String(),
			"totalAmount":     eventData.TotalAmount.String(),
			"tier":            float64(eventData.Tier),
			"tierName":        eventData.TierName,
			"tierSymbol":      eventData.TierSymbol,
			"depositTime":     eventData.DepositTime.String(),
			"lockEndTime":     eventData.LockEndTime.String(),
			"redeemTime":      eventData.RedeemTime.String(),
			"status":          float64(models.StatusClaimRequested),
			"user_region":     userRegion,
		},
		CreatedAt: time.Now(),
	}

	if err := repository.IRepo.Create("vault_events", &event); err != nil {
		log.Printf("Error saving ClaimRequested event: %v", err)
		return
	}

	if err := s.vaultService.ProcessClaimRequestedEvent(&event); err != nil {
		log.Printf("Error processing ClaimRequested event: %v", err)
	} else {
		log.Printf("Successfully processed ClaimRequested event for user %s, position %s", userAddress, positionId.String())
	}
}

// processPaymentProcessedEvent handles PaymentProcessed events from Raze Reserve vault
// This is emitted when the issuer sends money to the investor → status changes to Completed (3)
func (s *VaultBlockchainListener) processPaymentProcessedEvent(chainID int64, eventLog types.Log) {
	log.Printf("[PaymentProcessed] Block: %d, Tx: %s, Contract: %s",
		eventLog.BlockNumber, eventLog.TxHash.Hex(), eventLog.Address.Hex())

	// Extract indexed parameters
	var userAddress string
	var positionId *big.Int
	if len(eventLog.Topics) >= 2 {
		userAddress = strings.ToLower(common.HexToAddress(eventLog.Topics[1].Hex()).Hex())
	}
	if len(eventLog.Topics) >= 3 {
		positionId = new(big.Int).SetBytes(eventLog.Topics[2][:])
	}

	// Duplicate check
	txHash := eventLog.TxHash.Hex()
	var existingEvent models.VaultEvent
	err := repository.IRepo.FindOneWhere("vault_events", bson.M{
		"tx_hash":           txHash,
		"event_type":        "PaymentProcessed",
		"params.user":       userAddress,
		"params.positionId": positionId.String(),
	}, &existingEvent)
	if err == nil {
		log.Printf("[PaymentProcessed] Skipping duplicate event: tx=%s, user=%s, position=%s", txHash, userAddress, positionId.String())
		return
	}

	// Parse non-indexed parameters
	parsedABI, err := abi.JSON(strings.NewReader(razeReserveVaultABI))
	if err != nil {
		log.Printf("Error parsing Raze Reserve ABI: %v", err)
		return
	}

	type PaymentProcessedEventData struct {
		PrincipalAmount *big.Int
		RewardPaid      *big.Int
		TotalPaid       *big.Int
		Tier            uint8
		ProcessTime     *big.Int
	}

	var eventData PaymentProcessedEventData
	err = parsedABI.UnpackIntoInterface(&eventData, "PaymentProcessed", eventLog.Data)
	if err != nil {
		log.Printf("Error decoding PaymentProcessed event data: %v", err)
		return
	}

	project := getProjectFromContractAddress(eventLog.Address.Hex(), chainID)
	userRegion := getUserRegionFromContract(eventLog.Address.Hex(), chainID, project)

	event := models.VaultEvent{
		ChainID:         chainID,
		Project:         project,
		BlockNumber:     int64(eventLog.BlockNumber),
		TxHash:          eventLog.TxHash.Hex(),
		EventType:       "PaymentProcessed",
		ContractAddress: eventLog.Address.Hex(),
		Params: map[string]interface{}{
			"user":            userAddress,
			"positionId":      positionId.String(),
			"principalAmount": eventData.PrincipalAmount.String(),
			"rewardPaid":      eventData.RewardPaid.String(),
			"totalPaid":       eventData.TotalPaid.String(),
			"tier":            float64(eventData.Tier),
			"processTime":     eventData.ProcessTime.String(),
			"status":          float64(models.StatusCompleted),
			"user_region":     userRegion,
		},
		CreatedAt: time.Now(),
	}

	if err := repository.IRepo.Create("vault_events", &event); err != nil {
		log.Printf("Error saving PaymentProcessed event: %v", err)
		return
	}

	if err := s.vaultService.ProcessPaymentProcessedEvent(&event); err != nil {
		log.Printf("Error processing PaymentProcessed event: %v", err)
	} else {
		log.Printf("Successfully processed PaymentProcessed event for user %s, position %s", userAddress, positionId.String())
	}
}

func (s *VaultBlockchainListener) processContractPausedEvent(chainID int64, eventLog types.Log) {
	log.Printf("[ContractPaused] Block: %d, Tx: %s, Contract: %s",
		eventLog.BlockNumber, eventLog.TxHash.Hex(), eventLog.Address.Hex())

	// Extract indexed parameters
	var adminAddress string
	if len(eventLog.Topics) >= 2 {
		adminAddress = common.HexToAddress(eventLog.Topics[1].Hex()).Hex()
	}

	// Parse non-indexed parameters using COMPLETE ABI
	parsedABI, err := abi.JSON(strings.NewReader(vaultContractABI))
	if err != nil {
		log.Printf("Error parsing vault ABI: %v", err)
		return
	}

	// FIXED: Structure matches contract event order exactly
	type ContractPausedEventData struct {
		Timestamp *big.Int
	}

	var eventData ContractPausedEventData
	err = parsedABI.UnpackIntoInterface(&eventData, "ContractPaused", eventLog.Data)
	if err != nil {
		log.Printf("Error decoding ContractPaused event data: %v", err)
		return
	}

	event := models.VaultEvent{
		ChainID:         chainID,
		Project:         getProjectFromContractAddress(eventLog.Address.Hex(), chainID),
		BlockNumber:     int64(eventLog.BlockNumber),
		TxHash:          eventLog.TxHash.Hex(),
		EventType:       "ContractPaused",
		ContractAddress: eventLog.Address.Hex(),
		Params: map[string]interface{}{
			"admin":     adminAddress,
			"timestamp": eventData.Timestamp.String(),
		},
		CreatedAt: time.Now(),
	}

	if err := repository.IRepo.Create("vault_events", &event); err != nil {
		log.Printf("Error saving ContractPaused event: %v", err)
	} else {
		log.Printf("Successfully saved ContractPaused event by admin %s", adminAddress)
	}

	// Update vault status in database (for Compute Labs only)
	project := getProjectFromContractAddress(eventLog.Address.Hex(), chainID)
	if project == "compute_labs" {
		s.updateVaultStatus(chainID, eventLog.Address.Hex(), project, false, "ContractPaused",
			eventLog.TxHash.Hex(), eventLog.BlockNumber, adminAddress, eventData.Timestamp.Int64())
	}
}

func (s *VaultBlockchainListener) processContractUnpausedEvent(chainID int64, eventLog types.Log) {
	log.Printf("[ContractUnpaused] Block: %d, Tx: %s, Contract: %s",
		eventLog.BlockNumber, eventLog.TxHash.Hex(), eventLog.Address.Hex())

	// Extract indexed parameters
	var adminAddress string
	if len(eventLog.Topics) >= 2 {
		adminAddress = common.HexToAddress(eventLog.Topics[1].Hex()).Hex()
	}

	// Parse non-indexed parameters using COMPLETE ABI
	parsedABI, err := abi.JSON(strings.NewReader(vaultContractABI))
	if err != nil {
		log.Printf("Error parsing vault ABI: %v", err)
		return
	}

	// FIXED: Structure matches contract event order exactly
	type ContractUnpausedEventData struct {
		Timestamp *big.Int
	}

	var eventData ContractUnpausedEventData
	err = parsedABI.UnpackIntoInterface(&eventData, "ContractUnpaused", eventLog.Data)
	if err != nil {
		log.Printf("Error decoding ContractUnpaused event data: %v", err)
		return
	}

	event := models.VaultEvent{
		ChainID:         chainID,
		Project:         getProjectFromContractAddress(eventLog.Address.Hex(), chainID),
		BlockNumber:     int64(eventLog.BlockNumber),
		TxHash:          eventLog.TxHash.Hex(),
		EventType:       "ContractUnpaused",
		ContractAddress: eventLog.Address.Hex(),
		Params: map[string]interface{}{
			"admin":     adminAddress,
			"timestamp": eventData.Timestamp.String(),
		},
		CreatedAt: time.Now(),
	}

	if err := repository.IRepo.Create("vault_events", &event); err != nil {
		log.Printf("Error saving ContractUnpaused event: %v", err)
	} else {
		log.Printf("Successfully saved ContractUnpaused event by admin %s", adminAddress)
	}

	// Update vault status in database (for Compute Labs only)
	project := getProjectFromContractAddress(eventLog.Address.Hex(), chainID)
	if project == "compute_labs" {
		s.updateVaultStatus(chainID, eventLog.Address.Hex(), project, true, "ContractUnpaused",
			eventLog.TxHash.Hex(), eventLog.BlockNumber, adminAddress, eventData.Timestamp.Int64())
	}
}

func (s *VaultBlockchainListener) processVaultClosedEvent(chainID int64, eventLog types.Log) {
	log.Printf("[VaultClosedToNewInvestments] Block: %d, Tx: %s, Contract: %s",
		eventLog.BlockNumber, eventLog.TxHash.Hex(), eventLog.Address.Hex())

	// Extract indexed parameters
	var adminAddress string
	if len(eventLog.Topics) >= 2 {
		adminAddress = common.HexToAddress(eventLog.Topics[1].Hex()).Hex()
	}

	// Parse non-indexed parameters using Compute Labs ABI
	parsedABI, err := abi.JSON(strings.NewReader(computeLabsVaultABI))
	if err != nil {
		log.Printf("Error parsing Compute Labs vault ABI: %v", err)
		return
	}

	// Structure matches contract event order
	type VaultClosedEventData struct {
		Timestamp *big.Int
	}

	var eventData VaultClosedEventData
	err = parsedABI.UnpackIntoInterface(&eventData, "VaultClosedToNewInvestments", eventLog.Data)
	if err != nil {
		log.Printf("Error decoding VaultClosedToNewInvestments event data: %v", err)
		return
	}

	event := models.VaultEvent{
		ChainID:         chainID,
		Project:         getProjectFromContractAddress(eventLog.Address.Hex(), chainID),
		BlockNumber:     int64(eventLog.BlockNumber),
		TxHash:          eventLog.TxHash.Hex(),
		EventType:       "VaultClosedToNewInvestments",
		ContractAddress: eventLog.Address.Hex(),
		Params: map[string]interface{}{
			"admin":     adminAddress,
			"timestamp": eventData.Timestamp.String(),
		},
		CreatedAt: time.Now(),
	}

	if err := repository.IRepo.Create("vault_events", &event); err != nil {
		log.Printf("Error saving VaultClosedToNewInvestments event: %v", err)
	} else {
		log.Printf("Successfully saved VaultClosedToNewInvestments event by admin %s", adminAddress)
	}

	// Update vault status in database (for Compute Labs only)
	project := getProjectFromContractAddress(eventLog.Address.Hex(), chainID)
	if project == "compute_labs" {
		s.updateVaultStatus(chainID, eventLog.Address.Hex(), project, false, "VaultClosedToNewInvestments",
			eventLog.TxHash.Hex(), eventLog.BlockNumber, adminAddress, eventData.Timestamp.Int64())
	}
}

func (s *VaultBlockchainListener) processVaultReopenedEvent(chainID int64, eventLog types.Log) {
	log.Printf("[VaultReopened] Block: %d, Tx: %s, Contract: %s",
		eventLog.BlockNumber, eventLog.TxHash.Hex(), eventLog.Address.Hex())

	// Extract indexed parameters
	var adminAddress string
	if len(eventLog.Topics) >= 2 {
		adminAddress = common.HexToAddress(eventLog.Topics[1].Hex()).Hex()
	}

	// Parse non-indexed parameters using Compute Labs ABI
	parsedABI, err := abi.JSON(strings.NewReader(computeLabsVaultABI))
	if err != nil {
		log.Printf("Error parsing Compute Labs vault ABI: %v", err)
		return
	}

	// Structure matches contract event order
	type VaultReopenedEventData struct {
		Timestamp *big.Int
	}

	var eventData VaultReopenedEventData
	err = parsedABI.UnpackIntoInterface(&eventData, "VaultReopened", eventLog.Data)
	if err != nil {
		log.Printf("Error decoding VaultReopened event data: %v", err)
		return
	}

	event := models.VaultEvent{
		ChainID:         chainID,
		Project:         getProjectFromContractAddress(eventLog.Address.Hex(), chainID),
		BlockNumber:     int64(eventLog.BlockNumber),
		TxHash:          eventLog.TxHash.Hex(),
		EventType:       "VaultReopened",
		ContractAddress: eventLog.Address.Hex(),
		Params: map[string]interface{}{
			"admin":     adminAddress,
			"timestamp": eventData.Timestamp.String(),
		},
		CreatedAt: time.Now(),
	}

	if err := repository.IRepo.Create("vault_events", &event); err != nil {
		log.Printf("Error saving VaultReopened event: %v", err)
	} else {
		log.Printf("Successfully saved VaultReopened event by admin %s", adminAddress)
	}

	// Update vault status in database (for Compute Labs only)
	project := getProjectFromContractAddress(eventLog.Address.Hex(), chainID)
	if project == "compute_labs" {
		s.updateVaultStatus(chainID, eventLog.Address.Hex(), project, true, "VaultReopened",
			eventLog.TxHash.Hex(), eventLog.BlockNumber, adminAddress, eventData.Timestamp.Int64())
	}
}

// updateVaultStatus updates the vault status document in the database
// This is called when ContractPaused/Unpaused events are processed
func (s *VaultBlockchainListener) updateVaultStatus(chainID int64, contractAddress string, project string,
	isOpen bool, eventType string, txHash string, blockNumber uint64, admin string, timestamp int64) {

	status := "closed"
	if isOpen {
		status = "open"
	}

	eventTime := time.Unix(timestamp, 0)
	now := time.Now()

	// Upsert vault status document
	filter := bson.M{
		"chain_id":         chainID,
		"contract_address": strings.ToLower(contractAddress),
		"project":          project,
	}

	update := bson.M{
		"$set": bson.M{
			"is_open":            isOpen,
			"status":             status,
			"last_event_type":    eventType,
			"last_event_tx_hash": txHash,
			"last_event_block":   blockNumber,
			"last_event_time":    eventTime,
			"last_event_admin":   admin,
			"updated_at":         now,
		},
		"$setOnInsert": bson.M{
			"created_at": now,
		},
	}

	err := repository.IRepo.UpdateOne(models.ComputeLabsVaultStatusCollection, filter, update, true)
	if err != nil {
		log.Printf("❌ Error updating vault status: %v", err)
	} else {
		log.Printf("✅ Updated vault status: project=%s, chainID=%d, isOpen=%v, event=%s", project, chainID, isOpen, eventType)
	}
}

func (s *VaultBlockchainListener) processXTFTokensTransferredEvent(chainID int64, eventLog types.Log) {
	log.Printf("[XTFTokensTransferred] Block: %d, Tx: %s, Contract: %s",
		eventLog.BlockNumber, eventLog.TxHash.Hex(), eventLog.Address.Hex())

	// Extract indexed parameters (from, to, positionId)
	var toAddress string
	var positionId *big.Int
	// Skip Topics[0] (event signature) and Topics[1] (from address)
	if len(eventLog.Topics) >= 3 {
		toAddress = common.HexToAddress(eventLog.Topics[2].Hex()).Hex()
	}
	if len(eventLog.Topics) >= 4 {
		positionId = new(big.Int).SetBytes(eventLog.Topics[3][:])
	}

	// Parse non-indexed parameters (amount, timestamp)
	parsedABI, err := abi.JSON(strings.NewReader(vaultContractABI))
	if err != nil {
		log.Printf("Error parsing vault ABI: %v", err)
		return
	}

	type XTFTokensTransferredEventData struct {
		Amount    *big.Int
		Timestamp *big.Int
	}

	var eventData XTFTokensTransferredEventData
	err = parsedABI.UnpackIntoInterface(&eventData, "XTFTokensTransferred", eventLog.Data)
	if err != nil {
		log.Printf("Error decoding XTFTokensTransferred event data: %v", err)
		return
	}

	// Convert amount from base units (6 decimals for USDT/XTF tokens)
	tokenAmountFloat, err := convertFromBaseUnits(eventData.Amount.String(), USDT_DECIMALS)
	if err != nil {
		log.Printf("Error converting token amount: %v", err)
		return
	}

	// Determine token name based on which vault contract emitted the event
	contractAddress := strings.ToLower(eventLog.Address.Hex())
	ferroxNonUSContract := strings.ToLower(viper.GetString("vault.chains.xdc.contract_address"))
	ferroxUSContract := strings.ToLower(viper.GetString("vault.chains.xdc_ferrox_us.contract_address"))

	var tokenName string
	if ferroxUSContract != "" && contractAddress == ferroxUSContract {
		tokenName = "XTF-US" // US Ferrox token
		log.Printf("🇺🇸 [US Ferrox] Detected US Ferrox vault contract")
	} else if contractAddress == ferroxNonUSContract {
		tokenName = "XTF" // Non-US Ferrox token
		log.Printf("🌍 [Non-US Ferrox] Detected Non-US Ferrox vault contract")
	} else {
		tokenName = "XTF" // Default fallback
		log.Printf("⚠️ [Unknown Contract] Using default token name XTF for contract: %s", contractAddress)
	}

	log.Printf("📋 [XTFTokensTransferred] Position %s: %.2f %s tokens minted to %s (tx: %s)",
		positionId.String(), tokenAmountFloat, tokenName, toAddress, eventLog.TxHash.Hex())

	// Update VaultPosition with mint information
	// Note: user_address uses lowercase (stored lowercase in DB)
	// contract_address uses case-insensitive regex to match old records with mixed case
	filter := bson.M{
		"user_address": strings.ToLower(toAddress),
		"chain_id":     chainID,
		"contract_address": bson.M{
			"$regex":   "^" + strings.ToLower(eventLog.Address.Hex()) + "$",
			"$options": "i", // case-insensitive
		},
		"position_id": positionId.Uint64(),
	}

	mintTime := time.Now()
	update := bson.M{
		"$set": bson.M{
			"mint_hash":         eventLog.TxHash.Hex(),
			"mint_tx_status":    "confirmed",
			"mint_tx_time":      mintTime,
			"mint_token_amount": tokenAmountFloat,
			"mint_token_name":   tokenName, // Dynamic token name (XTF or XTF-US)
			"updated_at":        time.Now(),
		},
	}

	err = repository.IRepo.UpdateOne("vault_positions", filter, update, false)
	if err != nil {
		log.Printf("❌ Error updating VaultPosition with mint data: %v", err)
	} else {
		log.Printf("✅ Updated VaultPosition %s with XDC mint data: hash=%s, amount=%.2f %s",
			positionId.String(), eventLog.TxHash.Hex(), tokenAmountFloat, tokenName)
	}
}

// Helper function to convert from base units to readable format
func convertFromBaseUnits(amountStr string, decimals int) (float64, error) {
	if amountStr == "" || amountStr == "0" {
		return 0.0, nil
	}

	amount, ok := new(big.Int).SetString(amountStr, 10)
	if !ok {
		return 0.0, fmt.Errorf("invalid amount string: %s", amountStr)
	}

	// Convert to proper decimal places
	divisor := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil)

	// Convert to float64 with proper decimals
	floatAmount := float64(amount.Int64()) / float64(divisor.Int64())

	return floatAmount, nil
}

// ==================================================================================
// MANUAL TRIGGER FUNCTIONS - Reprocess existing blockchain transactions
// ==================================================================================

// ManualTriggerRequest defines the structure for manual event reprocessing
type ManualTriggerRequest struct {
	ChainID         int64  `json:"chain_id"`          // Required: blockchain chain ID
	TxHash          string `json:"tx_hash"`           // Optional: specific transaction hash
	BlockNumber     int64  `json:"block_number"`      // Optional: specific block number
	BlockRangeStart int64  `json:"block_range_start"` // Optional: start block for range
	BlockRangeEnd   int64  `json:"block_range_end"`   // Optional: end block for range
	EventType       string `json:"event_type"`        // Optional: filter by event type
	ContractAddress string `json:"contract_address"`  // Optional: filter by contract address
	UserAddress     string `json:"user_address"`      // Optional: filter by user wallet address
	PositionID      uint64 `json:"position_id"`       // Optional: filter by position ID (use with user_address)
	ForceReprocess  bool   `json:"force_reprocess"`   // If true, reprocess even if already processed
}

// ManualTriggerResponse provides detailed feedback about the reprocessing operation
type ManualTriggerResponse struct {
	Success           bool     `json:"success"`
	Message           string   `json:"message"`
	EventsFound       int      `json:"events_found"`
	EventsProcessed   int      `json:"events_processed"`
	EventsFailed      int      `json:"events_failed"`
	EventsSkipped     int      `json:"events_skipped"`
	ProcessedTxHashes []string `json:"processed_tx_hashes"`
	Errors            []string `json:"errors,omitempty"`
}

// ManualTriggerByTxHash manually reprocesses a specific transaction by its hash
// This function retrieves the transaction from the blockchain and reprocesses all its events
func (s *VaultBlockchainListener) ManualTriggerByTxHash(chainID int64, txHash string, forceReprocess bool) (*ManualTriggerResponse, error) {
	log.Printf("🎯 [Manual Trigger] Starting manual trigger for tx_hash: %s on chain %d", txHash, chainID)

	response := &ManualTriggerResponse{
		Success:           false,
		ProcessedTxHashes: []string{},
		Errors:            []string{},
	}

	// Get the client for this chain
	client, exists := s.clients[chainID]
	if !exists {
		errMsg := fmt.Sprintf("No client found for chain %d", chainID)
		response.Message = errMsg
		return response, fmt.Errorf(errMsg)
	}

	ctx := context.Background()

	// Get transaction receipt
	txHashCommon := common.HexToHash(txHash)
	receipt, err := client.TransactionReceipt(ctx, txHashCommon)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to get transaction receipt: %v", err)
		response.Message = errMsg
		response.Errors = append(response.Errors, errMsg)
		return response, err
	}

	log.Printf("📦 [Manual Trigger] Transaction found at block %d with %d logs", receipt.BlockNumber.Uint64(), len(receipt.Logs))

	// Event signatures
	vaultDepositSig := crypto.Keccak256Hash([]byte("VaultDeposit(address,uint256,uint8,uint256,uint256,uint256,bool,uint256,uint256,string,string,uint256,uint256)"))
	knotsVaultDepositSig := crypto.Keccak256Hash([]byte("VaultDeposit(address,uint256,uint8,uint256,uint256,uint256,uint256,uint256,string,string,uint256,uint256)"))
	razeReserveVaultDepositSig := crypto.Keccak256Hash([]byte("VaultDeposit(address,uint256,uint8,uint256,uint256,uint256,string,string,uint256,uint256,bool,uint256)"))
	vaultRedeemedSig := crypto.Keccak256Hash([]byte("VaultRedeemed(address,uint256,uint256,uint256,uint256,uint256,uint8,string,string,uint256,uint256,uint256)"))
	redemptionRequestedSig := crypto.Keccak256Hash([]byte("RedemptionRequested(address,uint256,uint256,uint256,uint8,uint256,uint256)"))
	positionStatusUpdatedSig := crypto.Keccak256Hash([]byte("PositionStatusUpdated(address,uint256,uint8,uint8,uint256)"))
	vaultRolledOverSig := crypto.Keccak256Hash([]byte("VaultRolledOver(address,uint256,uint256,uint256,uint8)"))
	razeReserveVaultRedeemedSig := crypto.Keccak256Hash([]byte("VaultRedeemed(address,uint256,uint256,uint256,uint256,uint8,string,string,uint256,uint256,uint256,uint256)"))
	contractPausedSig := crypto.Keccak256Hash([]byte("ContractPaused(address,uint256)"))
	contractUnpausedSig := crypto.Keccak256Hash([]byte("ContractUnpaused(address,uint256)"))
	xtfTokensTransferredSig := crypto.Keccak256Hash([]byte("XTFTokensTransferred(address,address,uint256,uint256,uint256)"))

	// Compute Labs event signatures
	distributionClaimedSig := crypto.Keccak256Hash([]byte("DistributionClaimed(address,uint256,uint256,uint256,uint256)"))
	distributionScheduleInitiatedSig := crypto.Keccak256Hash([]byte("DistributionScheduleInitiated(address,uint256,uint256)"))
	buyoutScheduledSig := crypto.Keccak256Hash([]byte("BuyoutScheduled(address,uint256,uint256)"))
	buyoutExecutedSig := crypto.Keccak256Hash([]byte("BuyoutExecuted(address,uint256,uint256)"))
	clgpuTokensTransferredSig := crypto.Keccak256Hash([]byte("CLGPUTokensTransferred(address,address,uint256,uint256,uint256)"))
	vaultClosedToNewInvestmentsSig := crypto.Keccak256Hash([]byte("VaultClosedToNewInvestments(address,uint256)"))
	vaultReopenedSig := crypto.Keccak256Hash([]byte("VaultReopened(address,uint256)"))

	response.EventsFound = len(receipt.Logs)

	// Process each log in the transaction
	for _, vLog := range receipt.Logs {
		if len(vLog.Topics) == 0 {
			continue
		}

		eventSig := vLog.Topics[0]
		var eventName string
		var shouldProcess bool = false

		// Identify the event type
		switch eventSig {
		case vaultDepositSig, knotsVaultDepositSig, razeReserveVaultDepositSig:
			eventName = "VaultDeposit"
			shouldProcess = true
		case vaultRedeemedSig, razeReserveVaultRedeemedSig:
			eventName = "VaultRedeemed"
			shouldProcess = true
		case redemptionRequestedSig:
			eventName = "RedemptionRequested"
			shouldProcess = true
		case positionStatusUpdatedSig:
			eventName = "PositionStatusUpdated"
			shouldProcess = true
		case vaultRolledOverSig:
			eventName = "VaultRolledOver"
			shouldProcess = true
		case contractPausedSig:
			eventName = "ContractPaused"
			shouldProcess = true
		case contractUnpausedSig:
			eventName = "ContractUnpaused"
			shouldProcess = true
		case xtfTokensTransferredSig:
			eventName = "XTFTokensTransferred"
			shouldProcess = true
		case distributionClaimedSig:
			eventName = "DistributionClaimed"
			shouldProcess = true
		case distributionScheduleInitiatedSig:
			eventName = "DistributionScheduleInitiated"
			shouldProcess = true
		case buyoutScheduledSig:
			eventName = "BuyoutScheduled"
			shouldProcess = true
		case buyoutExecutedSig:
			eventName = "BuyoutExecuted"
			shouldProcess = true
		case clgpuTokensTransferredSig:
			eventName = "CLGPUTokensTransferred"
			shouldProcess = true
		case vaultClosedToNewInvestmentsSig:
			eventName = "VaultClosedToNewInvestments"
			shouldProcess = true
		case vaultReopenedSig:
			eventName = "VaultReopened"
			shouldProcess = true
		default:
			log.Printf("⏭️  [Manual Trigger] Skipping unknown event signature: %s", eventSig.Hex())
			response.EventsSkipped++
			continue
		}

		if !shouldProcess {
			continue
		}

		log.Printf("🔍 [Manual Trigger] Processing %s event from tx %s", eventName, txHash)

		// Check if already processed (unless force reprocess is enabled)
		if !forceReprocess {
			var existingEvent models.VaultEvent
			err := repository.IRepo.FindOneWhere("vault_events", bson.M{
				"tx_hash":    txHash,
				"event_type": eventName,
			}, &existingEvent)
			if err == nil {
				log.Printf("⚠️  [Manual Trigger] Event %s already processed for tx %s, skipping", eventName, txHash)
				response.EventsSkipped++
				continue
			}
		}

		// Process the event based on its type
		switch eventSig {
		case vaultDepositSig, knotsVaultDepositSig, razeReserveVaultDepositSig:
			s.processVaultDepositEvent(chainID, *vLog)
		case vaultRedeemedSig, razeReserveVaultRedeemedSig:
			s.processVaultRedeemedEvent(chainID, *vLog)
		case redemptionRequestedSig:
			s.processRedemptionRequestedEvent(chainID, *vLog)
		case positionStatusUpdatedSig:
			s.processPositionStatusUpdatedEvent(chainID, *vLog)
		case vaultRolledOverSig:
			s.processVaultRolledOverEvent(chainID, *vLog)
		case contractPausedSig:
			s.processContractPausedEvent(chainID, *vLog)
		case contractUnpausedSig:
			s.processContractUnpausedEvent(chainID, *vLog)
		case vaultClosedToNewInvestmentsSig:
			s.processVaultClosedEvent(chainID, *vLog)
		case vaultReopenedSig:
			s.processVaultReopenedEvent(chainID, *vLog)
		case xtfTokensTransferredSig:
			s.processXTFTokensTransferredEvent(chainID, *vLog)
		case distributionClaimedSig:
			s.processDistributionClaimedEvent(chainID, *vLog)
		case distributionScheduleInitiatedSig:
			s.processDistributionScheduleInitiatedEvent(chainID, *vLog)
		case buyoutScheduledSig:
			s.processBuyoutScheduledEvent(chainID, *vLog)
		case buyoutExecutedSig:
			s.processBuyoutExecutedEvent(chainID, *vLog)
		case clgpuTokensTransferredSig:
			s.processCLGPUTokensTransferredEvent(chainID, *vLog)
		}

		log.Printf("✅ [Manual Trigger] Successfully processed %s event", eventName)
		response.EventsProcessed++
	}

	response.ProcessedTxHashes = append(response.ProcessedTxHashes, txHash)
	response.Success = response.EventsProcessed > 0
	response.Message = fmt.Sprintf("Processed %d events out of %d found for tx %s",
		response.EventsProcessed, response.EventsFound, txHash)

	log.Printf("🎉 [Manual Trigger] Completed: %s", response.Message)
	return response, nil
}

// ManualTriggerByBlockRange manually reprocesses all events within a block range
// This function scans blocks and reprocesses all vault-related events
func (s *VaultBlockchainListener) ManualTriggerByBlockRange(chainID int64, startBlock, endBlock int64, eventTypeFilter string, forceReprocess bool) (*ManualTriggerResponse, error) {
	log.Printf("🎯 [Manual Trigger] Starting block range trigger: chain=%d, blocks=%d-%d, eventType=%s",
		chainID, startBlock, endBlock, eventTypeFilter)

	response := &ManualTriggerResponse{
		Success:           false,
		ProcessedTxHashes: []string{},
		Errors:            []string{},
	}

	// Validate block range
	if startBlock > endBlock {
		errMsg := "Start block must be less than or equal to end block"
		response.Message = errMsg
		return response, fmt.Errorf(errMsg)
	}

	// Limit range to prevent overwhelming the system
	maxBlockRange := int64(1000)
	if endBlock-startBlock > maxBlockRange {
		errMsg := fmt.Sprintf("Block range too large (max %d blocks). Please use smaller ranges.", maxBlockRange)
		response.Message = errMsg
		return response, fmt.Errorf(errMsg)
	}

	// Get the client for this chain
	client, exists := s.clients[chainID]
	if !exists {
		errMsg := fmt.Sprintf("No client found for chain %d", chainID)
		response.Message = errMsg
		return response, fmt.Errorf(errMsg)
	}

	ctx := context.Background()

	// Get contract addresses for this chain
	contractAddresses, exists := s.contractAddresses[chainID]
	if !exists || len(contractAddresses) == 0 {
		errMsg := fmt.Sprintf("No contract addresses configured for chain %d", chainID)
		response.Message = errMsg
		return response, fmt.Errorf(errMsg)
	}

	// Event signatures
	eventSignatures := map[string]common.Hash{
		"VaultDeposit":                    crypto.Keccak256Hash([]byte("VaultDeposit(address,uint256,uint8,uint256,uint256,uint256,bool,uint256,uint256,string,string,uint256,uint256)")),
		"KnotsVaultDeposit":               crypto.Keccak256Hash([]byte("VaultDeposit(address,uint256,uint8,uint256,uint256,uint256,uint256,uint256,string,string,uint256,uint256)")),
		"ComputeLabsVaultDeposit":         crypto.Keccak256Hash([]byte("VaultDeposit(address,uint256,uint256,uint256,uint256,uint256,uint256,string,string,uint256,uint256)")),
		"RazeReserveVaultDeposit":         crypto.Keccak256Hash([]byte("VaultDeposit(address,uint256,uint8,uint256,uint256,uint256,string,string,uint256,uint256,bool,uint256)")),
		"VaultRedeemed":                   crypto.Keccak256Hash([]byte("VaultRedeemed(address,uint256,uint256,uint256,uint256,uint256,uint8,string,string,uint256,uint256,uint256)")),
		"ComputeLabsVaultRedeemed":        crypto.Keccak256Hash([]byte("VaultRedeemed(address,uint256,uint256,uint256,uint256,uint256,string,string,uint256,uint256)")),
		"RedemptionRequested":             crypto.Keccak256Hash([]byte("RedemptionRequested(address,uint256,uint256,uint256,uint8,uint256,uint256)")),
		"PositionStatusUpdated":           crypto.Keccak256Hash([]byte("PositionStatusUpdated(address,uint256,uint8,uint8,uint256)")),
		"VaultRolledOver":                 crypto.Keccak256Hash([]byte("VaultRolledOver(address,uint256,uint256,uint256,uint8)")),
		"RazeReserveVaultRedeemed":        crypto.Keccak256Hash([]byte("VaultRedeemed(address,uint256,uint256,uint256,uint256,uint8,string,string,uint256,uint256,uint256,uint256)")),
		"ContractPaused":                  crypto.Keccak256Hash([]byte("ContractPaused(address,uint256)")),
		"ContractUnpaused":                crypto.Keccak256Hash([]byte("ContractUnpaused(address,uint256)")),
		"XTFTokensTransferred":            crypto.Keccak256Hash([]byte("XTFTokensTransferred(address,address,uint256,uint256,uint256)")),
		"DistributionClaimed":             crypto.Keccak256Hash([]byte("DistributionClaimed(address,uint256,uint256,uint256,uint256)")),
		"DistributionScheduleInitiated":   crypto.Keccak256Hash([]byte("DistributionScheduleInitiated(address,uint256,uint256)")),
		"BuyoutScheduled":                 crypto.Keccak256Hash([]byte("BuyoutScheduled(address,uint256,uint256)")),
		"BuyoutExecuted":                  crypto.Keccak256Hash([]byte("BuyoutExecuted(address,uint256,uint256)")),
		"CLGPUTokensTransferred":          crypto.Keccak256Hash([]byte("CLGPUTokensTransferred(address,address,uint256,uint256,uint256)")),
		"VaultClosedToNewInvestments":     crypto.Keccak256Hash([]byte("VaultClosedToNewInvestments(address,uint256)")),
		"VaultReopened":                   crypto.Keccak256Hash([]byte("VaultReopened(address,uint256)")),
	}

	// Build topics filter
	var topics [][]common.Hash
	if eventTypeFilter != "" {
		if sig, exists := eventSignatures[eventTypeFilter]; exists {
			topics = [][]common.Hash{{sig}}
		} else {
			errMsg := fmt.Sprintf("Unknown event type: %s", eventTypeFilter)
			response.Message = errMsg
			return response, fmt.Errorf(errMsg)
		}
	} else {
		// Include all event signatures
		allSigs := []common.Hash{}
		for _, sig := range eventSignatures {
			allSigs = append(allSigs, sig)
		}
		topics = [][]common.Hash{allSigs}
	}

	// Query logs for each contract address
	for _, contractAddr := range contractAddresses {
		log.Printf("🔍 [Manual Trigger] Querying logs for contract %s, blocks %d-%d", contractAddr.Hex(), startBlock, endBlock)

		query := ethereum.FilterQuery{
			FromBlock: big.NewInt(startBlock),
			ToBlock:   big.NewInt(endBlock),
			Addresses: []common.Address{contractAddr},
			Topics:    topics,
		}

		logs, err := client.FilterLogs(ctx, query)
		if err != nil {
			errMsg := fmt.Sprintf("Failed to filter logs for contract %s: %v", contractAddr.Hex(), err)
			log.Printf("❌ [Manual Trigger] %s", errMsg)
			response.Errors = append(response.Errors, errMsg)
			continue
		}

		log.Printf("📦 [Manual Trigger] Found %d events for contract %s", len(logs), contractAddr.Hex())
		response.EventsFound += len(logs)

		// Process each log
		for _, vLog := range logs {
			if len(vLog.Topics) == 0 {
				continue
			}

			eventSig := vLog.Topics[0]
			var eventName string

			// Find event name from signature
			for name, sig := range eventSignatures {
				if sig == eventSig {
					eventName = name
					break
				}
			}

			if eventName == "" {
				log.Printf("⏭️  [Manual Trigger] Unknown event signature: %s", eventSig.Hex())
				response.EventsSkipped++
				continue
			}

			log.Printf("🔍 [Manual Trigger] Processing %s event from tx %s", eventName, vLog.TxHash.Hex())

			// Check if already processed (unless force reprocess is enabled)
			if !forceReprocess {
				var existingEvent models.VaultEvent
				err := repository.IRepo.FindOneWhere("vault_events", bson.M{
					"tx_hash":    vLog.TxHash.Hex(),
					"event_type": eventName,
				}, &existingEvent)
				if err == nil {
					log.Printf("⚠️  [Manual Trigger] Event %s already processed for tx %s, skipping", eventName, vLog.TxHash.Hex())
					response.EventsSkipped++
					continue
				}
			}

			// Process the event
			switch eventName {
			case "VaultDeposit", "RazeReserveVaultDeposit":
				s.processVaultDepositEvent(chainID, vLog)
			case "VaultRedeemed":
				s.processVaultRedeemedEvent(chainID, vLog)
			case "RedemptionRequested":
				s.processRedemptionRequestedEvent(chainID, vLog)
			case "PositionStatusUpdated":
				s.processPositionStatusUpdatedEvent(chainID, vLog)
			case "VaultRolledOver":
				s.processVaultRolledOverEvent(chainID, vLog)
			// ClaimRequested and PaymentProcessed removed — Raze Reserve now uses VaultRedeemed
			case "ContractPaused":
				s.processContractPausedEvent(chainID, vLog)
			case "ContractUnpaused":
				s.processContractUnpausedEvent(chainID, vLog)
			case "XTFTokensTransferred":
				s.processXTFTokensTransferredEvent(chainID, vLog)
			case "DistributionClaimed":
				s.processDistributionClaimedEvent(chainID, vLog)
			case "DistributionScheduleInitiated":
				s.processDistributionScheduleInitiatedEvent(chainID, vLog)
			case "BuyoutScheduled":
				s.processBuyoutScheduledEvent(chainID, vLog)
			case "BuyoutExecuted":
				s.processBuyoutExecutedEvent(chainID, vLog)
			case "CLGPUTokensTransferred":
				s.processCLGPUTokensTransferredEvent(chainID, vLog)
			case "VaultClosedToNewInvestments":
				s.processVaultClosedEvent(chainID, vLog)
			case "VaultReopened":
				s.processVaultReopenedEvent(chainID, vLog)
			}

			response.EventsProcessed++
			if !contains(response.ProcessedTxHashes, vLog.TxHash.Hex()) {
				response.ProcessedTxHashes = append(response.ProcessedTxHashes, vLog.TxHash.Hex())
			}
		}
	}

	response.Success = response.EventsProcessed > 0
	response.Message = fmt.Sprintf("Processed %d events out of %d found in blocks %d-%d",
		response.EventsProcessed, response.EventsFound, startBlock, endBlock)

	log.Printf("🎉 [Manual Trigger] Completed: %s", response.Message)
	return response, nil
}

// ManualTriggerByStoredEvent manually reprocesses an event from the vault_events collection
// This is useful for replaying events that were previously stored but may have failed processing
func (s *VaultBlockchainListener) ManualTriggerByStoredEvent(eventID string) (*ManualTriggerResponse, error) {
	log.Printf("🎯 [Manual Trigger] Starting manual trigger for stored event ID: %s", eventID)

	response := &ManualTriggerResponse{
		Success:           false,
		ProcessedTxHashes: []string{},
		Errors:            []string{},
	}

	// Fetch the event from database
	var storedEvent models.VaultEvent
	err := repository.IRepo.FindOneWhere("vault_events", bson.M{"_id": eventID}, &storedEvent)
	if err != nil {
		errMsg := fmt.Sprintf("Event not found in database: %v", err)
		response.Message = errMsg
		response.Errors = append(response.Errors, errMsg)
		return response, err
	}

	log.Printf("📋 [Manual Trigger] Found stored event: type=%s, tx=%s, chain=%d",
		storedEvent.EventType, storedEvent.TxHash, storedEvent.ChainID)

	response.EventsFound = 1

	// Process the event using vault service
	var processErr error
	switch storedEvent.EventType {
	case "VaultDeposit":
		processErr = s.vaultService.ProcessVaultDepositEvent(&storedEvent)
	case "VaultRedeemed":
		processErr = s.vaultService.ProcessVaultRedeemedEvent(&storedEvent)
	case "RedemptionRequested":
		processErr = s.vaultService.ProcessRedemptionRequestedEvent(&storedEvent)
	case "PositionStatusUpdated":
		processErr = s.vaultService.ProcessPositionStatusUpdatedEvent(&storedEvent)
	case "VaultRolledOver":
		processErr = s.vaultService.ProcessVaultRolledOverEvent(&storedEvent)
	// ClaimRequested and PaymentProcessed removed — Raze Reserve now uses VaultRedeemed
	default:
		errMsg := fmt.Sprintf("Unknown or unsupported event type: %s", storedEvent.EventType)
		response.Message = errMsg
		response.Errors = append(response.Errors, errMsg)
		return response, fmt.Errorf(errMsg)
	}

	if processErr != nil {
		errMsg := fmt.Sprintf("Failed to process event: %v", processErr)
		log.Printf("❌ [Manual Trigger] %s", errMsg)
		response.EventsFailed = 1
		response.Errors = append(response.Errors, errMsg)
		response.Message = errMsg
	} else {
		log.Printf("✅ [Manual Trigger] Successfully reprocessed stored event")
		response.EventsProcessed = 1
		response.Success = true
		response.ProcessedTxHashes = append(response.ProcessedTxHashes, storedEvent.TxHash)
		response.Message = fmt.Sprintf("Successfully reprocessed stored event %s", eventID)
	}

	log.Printf("🎉 [Manual Trigger] Completed: %s", response.Message)
	return response, nil
}

// ManualTriggerByUserAndPosition manually reprocesses events for a specific user wallet and position ID
// This is useful when you need to replay events for a specific vault position
func (s *VaultBlockchainListener) ManualTriggerByUserAndPosition(chainID int64, userAddress string, positionID uint64, forceReprocess bool) (*ManualTriggerResponse, error) {
	log.Printf("🎯 [Manual Trigger] Starting manual trigger for user=%s, position=%d on chain %d",
		userAddress, positionID, chainID)

	response := &ManualTriggerResponse{
		Success:           false,
		ProcessedTxHashes: []string{},
		Errors:            []string{},
	}

	// Normalize user address to lowercase
	userAddress = strings.ToLower(userAddress)

	// Build query to find all events for this user and position
	query := bson.M{
		"chain_id":          chainID,
		"params.user":       userAddress,
		"params.positionId": fmt.Sprintf("%d", positionID),
	}

	log.Printf("🔍 [Manual Trigger] Querying vault_events with filter: %+v", query)

	// Query vault_events collection
	var events []models.VaultEvent
	err := repository.IRepo.GetAll("vault_events", query, &events)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to query vault events: %v", err)
		log.Printf("❌ [Manual Trigger] %s", errMsg)
		response.Message = errMsg
		response.Errors = append(response.Errors, errMsg)
		return response, err
	}

	if len(events) == 0 {
		msg := fmt.Sprintf("No events found for user %s, position %d on chain %d", userAddress, positionID, chainID)
		log.Printf("⚠️  [Manual Trigger] %s", msg)
		response.Message = msg
		return response, nil
	}

	log.Printf("📦 [Manual Trigger] Found %d stored events for user %s, position %d", len(events), userAddress, positionID)
	response.EventsFound = len(events)

	// Collect unique transaction hashes
	txHashMap := make(map[string]bool)
	for _, event := range events {
		if event.TxHash != "" {
			txHashMap[event.TxHash] = true
		}
	}

	log.Printf("🔍 [Manual Trigger] Found %d unique transactions to reprocess", len(txHashMap))

	// Reprocess each transaction
	for txHash := range txHashMap {
		log.Printf("🔄 [Manual Trigger] Reprocessing transaction: %s", txHash)

		txResponse, err := s.ManualTriggerByTxHash(chainID, txHash, forceReprocess)
		if err != nil {
			errMsg := fmt.Sprintf("Failed to reprocess tx %s: %v", txHash, err)
			log.Printf("❌ [Manual Trigger] %s", errMsg)
			response.Errors = append(response.Errors, errMsg)
			response.EventsFailed += txResponse.EventsFailed
			continue
		}

		// Aggregate results
		response.EventsProcessed += txResponse.EventsProcessed
		response.EventsFailed += txResponse.EventsFailed
		response.EventsSkipped += txResponse.EventsSkipped

		if !contains(response.ProcessedTxHashes, txHash) {
			response.ProcessedTxHashes = append(response.ProcessedTxHashes, txHash)
		}

		log.Printf("✅ [Manual Trigger] Completed tx %s: processed=%d, failed=%d, skipped=%d",
			txHash, txResponse.EventsProcessed, txResponse.EventsFailed, txResponse.EventsSkipped)
	}

	response.Success = response.EventsProcessed > 0
	response.Message = fmt.Sprintf("Processed %d events from %d transactions for user %s, position %d",
		response.EventsProcessed, len(response.ProcessedTxHashes), userAddress, positionID)

	log.Printf("🎉 [Manual Trigger] Completed: %s", response.Message)
	return response, nil
}

// ManualTrigger is the main entry point for manual event reprocessing
// It routes to the appropriate handler based on the request parameters
func (s *VaultBlockchainListener) ManualTrigger(req ManualTriggerRequest) (*ManualTriggerResponse, error) {
	log.Printf("🎯 [Manual Trigger] Received request: %+v", req)

	// Validate chain ID
	if req.ChainID == 0 {
		return &ManualTriggerResponse{
			Success: false,
			Message: "Chain ID is required",
		}, fmt.Errorf("chain ID is required")
	}

	// Route based on request parameters
	if req.UserAddress != "" && req.PositionID > 0 {
		// Process specific user and position
		return s.ManualTriggerByUserAndPosition(req.ChainID, req.UserAddress, req.PositionID, req.ForceReprocess)
	} else if req.UserAddress != "" {
		// Process all events for a user (position ID = 0 or not specified)
		// We'll treat position_id=0 specially - search for all positions
		return s.ManualTriggerByUserAndPosition(req.ChainID, req.UserAddress, req.PositionID, req.ForceReprocess)
	} else if req.TxHash != "" {
		// Process single transaction
		return s.ManualTriggerByTxHash(req.ChainID, req.TxHash, req.ForceReprocess)
	} else if req.BlockRangeStart > 0 && req.BlockRangeEnd > 0 {
		// Process block range
		return s.ManualTriggerByBlockRange(req.ChainID, req.BlockRangeStart, req.BlockRangeEnd, req.EventType, req.ForceReprocess)
	} else if req.BlockNumber > 0 {
		// Process single block (treat as range of 1)
		return s.ManualTriggerByBlockRange(req.ChainID, req.BlockNumber, req.BlockNumber, req.EventType, req.ForceReprocess)
	} else {
		return &ManualTriggerResponse{
			Success: false,
			Message: "Must specify either tx_hash, block_number, block_range, or user_address with position_id",
		}, fmt.Errorf("invalid request parameters")
	}
}

// verifyAndSupplementLogsFromReceipts checks if FilterLogs returned all events
// and supplements with missing events from transaction receipts if needed
func (s *VaultBlockchainListener) verifyAndSupplementLogsFromReceipts(
	ctx context.Context,
	client *ethclient.Client,
	vaultLogs []types.Log,
	contracts []common.Address,
	chainIndicator string,
	vaultDepositSig, knotsVaultDepositSig, computeLabsVaultDepositSig, vaultRedeemedSig, computeLabsVaultRedeemedSig, redemptionRequestedSig, positionStatusUpdatedSig,
	vaultRolledOverSig, contractPausedSig, contractUnpausedSig, xtfTokensTransferredSig,
	distributionClaimedSig, distributionScheduleInitiatedSig, buyoutScheduledSig, buyoutExecutedSig,
	vaultClosedToNewInvestmentsSig, vaultReopenedSig common.Hash) []types.Log {

	if len(vaultLogs) == 0 {
		return vaultLogs
	}

	// Group logs by transaction to detect potential truncation
	txEventCounts := make(map[common.Hash]int)
	for _, vLog := range vaultLogs {
		txEventCounts[vLog.TxHash]++
	}

	supplementedLogs := vaultLogs
	totalAdded := 0

	// Check each transaction for suspicious event counts that might indicate RPC truncation
	// Common RPC limits: 9, 10, 50, 100, 1000, 10000
	suspiciousCounts := map[int]bool{9: true, 10: true, 50: true, 99: true, 100: true, 500: true, 999: true, 1000: true, 10000: true}

	for txHash, count := range txEventCounts {
		// If the count matches a common truncation point, verify with receipt
		if suspiciousCounts[count] {
			log.Printf("⚠️ %s Transaction %s has suspicious event count (%d) - fetching full receipt to verify",
				chainIndicator, txHash.Hex(), count)

			// Fetch transaction receipt to get complete logs
			ctxWithTimeout, cancel := context.WithTimeout(ctx, 10*time.Second)
			receipt, err := client.TransactionReceipt(ctxWithTimeout, txHash)
			cancel()

			if err != nil {
				log.Printf("❌ %s Failed to fetch receipt for tx %s: %v", chainIndicator, txHash.Hex(), err)
				continue
			}

			// Count vault events in receipt
			receiptEventCount := 0
			var receiptVaultLogs []types.Log

			for _, rLog := range receipt.Logs {
				// Check if log is from our vault contracts
				isVaultContract := false
				for _, contractAddr := range contracts {
					if rLog.Address == contractAddr {
						isVaultContract = true
						break
					}
				}

				if isVaultContract && len(rLog.Topics) > 0 {
					// Check if it's a vault event we care about
					topicHash := rLog.Topics[0]
					if topicHash == vaultDepositSig ||
						topicHash == knotsVaultDepositSig ||
						topicHash == computeLabsVaultDepositSig ||
						topicHash == vaultRedeemedSig ||
						topicHash == computeLabsVaultRedeemedSig ||
						topicHash == redemptionRequestedSig ||
						topicHash == positionStatusUpdatedSig ||
						topicHash == vaultRolledOverSig ||
						topicHash == contractPausedSig ||
						topicHash == contractUnpausedSig ||
						topicHash == xtfTokensTransferredSig ||
						topicHash == distributionClaimedSig ||
						topicHash == distributionScheduleInitiatedSig ||
						topicHash == buyoutScheduledSig ||
						topicHash == buyoutExecutedSig ||
						topicHash == vaultClosedToNewInvestmentsSig ||
						topicHash == vaultReopenedSig {

						receiptEventCount++
						receiptVaultLogs = append(receiptVaultLogs, *rLog)
					}
				}
			}

			if receiptEventCount > count {
				log.Printf("🚨 %s MISSING EVENTS DETECTED! Transaction %s has %d events in receipt but FilterLogs returned only %d",
					chainIndicator, txHash.Hex(), receiptEventCount, count)
				log.Printf("🔄 %s Adding %d missing events from transaction receipt",
					chainIndicator, receiptEventCount-count)

				// Add missing logs from receipt
				for _, rLog := range receiptVaultLogs {
					// Check if this log is already in supplementedLogs
					found := false
					for _, vLog := range supplementedLogs {
						if vLog.TxHash == rLog.TxHash && vLog.Index == rLog.Index {
							found = true
							break
						}
					}

					if !found {
						log.Printf("➕ %s Adding missing event: tx=%s, index=%d, block=%d, topic=%s",
							chainIndicator, rLog.TxHash.Hex(), rLog.Index, rLog.BlockNumber, rLog.Topics[0].Hex())
						supplementedLogs = append(supplementedLogs, rLog)
						totalAdded++
					}
				}
			} else if receiptEventCount == count {
				log.Printf("✅ %s Transaction %s verified complete - no missing events",
					chainIndicator, txHash.Hex())
			} else {
				log.Printf("⚠️ %s Transaction %s: receipt has fewer events (%d) than FilterLogs (%d) - this is unexpected",
					chainIndicator, txHash.Hex(), receiptEventCount, count)
			}
		}
	}

	if totalAdded > 0 {
		log.Printf("✅ %s Successfully added %d missing events. Total events: %d → %d",
			chainIndicator, totalAdded, len(vaultLogs), len(supplementedLogs))
	}

	return supplementedLogs
}

// Helper function to check if a string slice contains a value
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// FixMissingEventsInBlock76630615 fixes the missing events in the specific problematic block
func (s *VaultBlockchainListener) FixMissingEventsInBlock76630615() error {
	blockNumber := big.NewInt(76630615)
	chainID := int64(51) // XDC Testnet
	txHash := "0x7d71234b479ba62cf07b269888ff112870fdab4793f7c8f37ab4045eaaece97d"

	log.Printf("🔧 Starting fix for missing events in block %s, tx %s", blockNumber.String(), txHash)

	// Get the client for this chain
	client, exists := s.clients[chainID]
	if !exists {
		return fmt.Errorf("no client configured for chain %d", chainID)
	}

	// Get transaction receipt
	ctx := context.Background()
	receipt, err := client.TransactionReceipt(ctx, common.HexToHash(txHash))
	if err != nil {
		return fmt.Errorf("failed to get transaction receipt: %v", err)
	}

	log.Printf("📊 Transaction has %d logs/events", len(receipt.Logs))

	// Count existing events in MongoDB
	var existingEvents []models.VaultEvent
	err = repository.IRepo.FindWhere("vault_events", bson.M{
		"tx_hash":    txHash,
		"event_type": "VaultRolledOver",
	}, &existingEvents)
	if err != nil {
		log.Printf("⚠️ Error checking existing events: %v", err)
		existingEvents = []models.VaultEvent{} // Initialize empty if error
	}

	log.Printf("📂 Found %d existing VaultRolledOver events in MongoDB for this tx", len(existingEvents))

	// Parse VaultRolledOver events
	vaultRolledOverSig := crypto.Keccak256Hash([]byte("VaultRolledOver(address,uint256,uint256,uint256,uint8)"))

	processedCount := 0

	for i, vLog := range receipt.Logs {
		if len(vLog.Topics) == 0 {
			continue
		}

		// Check if this is a VaultRolledOver event
		if vLog.Topics[0] != vaultRolledOverSig {
			continue
		}

		// Process the event using existing method
		s.processVaultRolledOverEvent(chainID, *vLog)
		processedCount++

		// Extract user and position for logging
		var userAddress string
		var positionId *big.Int
		if len(vLog.Topics) >= 2 {
			userAddress = common.HexToAddress(vLog.Topics[1].Hex()).Hex()
		}
		if len(vLog.Topics) >= 3 {
			positionId = new(big.Int).SetBytes(vLog.Topics[2][:])
		}

		log.Printf("📍 Processed event %d: User %s, Position %s", i, userAddress, positionId.String())
	}

	log.Printf("\n✅ Fix Summary:")
	log.Printf("  - Total VaultRolledOver events in tx: %d", processedCount)
	log.Printf("  - Events already in DB: %d", len(existingEvents))
	log.Printf("  - Expected new events: %d", processedCount-len(existingEvents))

	// Verify final count
	var finalEvents []models.VaultEvent
	err = repository.IRepo.FindWhere("vault_events", bson.M{
		"tx_hash":    txHash,
		"event_type": "VaultRolledOver",
	}, &finalEvents)
	if err == nil {
		log.Printf("  - Final events in DB: %d", len(finalEvents))
		if len(finalEvents) == 21 {
			log.Printf("  ✅ All 21 events are now in the database!")
		} else {
			log.Printf("  ⚠️ Expected 21 events but found %d", len(finalEvents))
		}
	}

	return nil
}
