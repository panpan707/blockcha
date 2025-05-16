#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>

#define MAX_TRANSACTIONS 10
#define DIFFICULTY 4  // Updated difficulty
#define BLOCKCHAIN_SIZE 100
#define HASH_SIZE 65
#define DATA_SIZE 1024

typedef struct {
    char sender[100];
    char recipient[100];
    double amount;
    time_t timestamp;
} Transaction;

typedef struct {
    int index;
    Transaction transactions[MAX_TRANSACTIONS];
    int transaction_count;
    time_t timestamp;
    char previous_hash[HASH_SIZE];
    char hash[HASH_SIZE];
    int nonce;
} Block;

typedef struct {
    Block blocks[BLOCKCHAIN_SIZE];
    int size;
    Transaction pending_transactions[MAX_TRANSACTIONS];
    int pending_count;
    double mining_reward;
    int difficulty;
} Blockchain;

// djb2 hash function adapted to hex string
void calculate_hash(Block *block, char *hash_output) {
    // Build data string to hash
    char data[DATA_SIZE] = {0};
    snprintf(data, DATA_SIZE, "%d", block->index);

    for (int i = 0; i < block->transaction_count; i++) {
        char tx[300];
        snprintf(tx, 300, "%s%s%.2f%ld",
                 block->transactions[i].sender,
                 block->transactions[i].recipient,
                 block->transactions[i].amount,
                 block->transactions[i].timestamp);
        strncat(data, tx, DATA_SIZE - strlen(data) - 1);
    }

    char time_str[20];
    snprintf(time_str, 20, "%ld", block->timestamp);
    strncat(data, time_str, DATA_SIZE - strlen(data) - 1);

    char nonce_str[20];
    snprintf(nonce_str, 20, "%d", block->nonce);
    strncat(data, nonce_str, DATA_SIZE - strlen(data) - 1);

    // Compute SHA256 hash
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)data, strlen(data), hash);

    // Convert to hex string
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hash_output + (i * 2), "%02x", hash[i]);
    }
    hash_output[64] = 0;  // null terminator
}


void mine_block(Block *block, int difficulty) {
    char target[HASH_SIZE];
    memset(target, '0', difficulty);
    target[difficulty] = '\0';

    while (1) {
        calculate_hash(block, block->hash);
        if (strncmp(block->hash, target, difficulty) == 0) {
            printf("Block mined: %s\n", block->hash);
            break;
        }
        block->nonce++;
    }
}

void init_blockchain(Blockchain *blockchain) {
    blockchain->size = 0;
    blockchain->pending_count = 0;
    blockchain->mining_reward = 10.0;
    blockchain->difficulty = DIFFICULTY;

    Block genesis;
    genesis.index = 0;
    genesis.transaction_count = 0;
    genesis.timestamp = time(NULL);
    strcpy(genesis.previous_hash, "0");
    genesis.nonce = 0;

    printf("Mining genesis block...\n");
    mine_block(&genesis, blockchain->difficulty);

    blockchain->blocks[0] = genesis;
    blockchain->size = 1;
    printf("Genesis block created\n");
}
double get_balance(Blockchain *blockchain, const char *wallet) {
    double balance = 0.0;

    // Iterate all blocks
    for (int i = 0; i < blockchain->size; i++) {
        Block *block = &blockchain->blocks[i];

        // Iterate all transactions
        for (int j = 0; j < block->transaction_count; j++) {
            Transaction *tx = &block->transactions[j];

            if (strcmp(tx->recipient, wallet) == 0) {
                balance += tx->amount;
            }

            if (strcmp(tx->sender, wallet) == 0) {
                balance -= tx->amount;
            }
        }
    }

    // Also consider pending transactions if you want (optional)

    return balance;
}


int add_transaction(Blockchain *blockchain, const char *sender, const char *recipient, double amount) {
       
    if (blockchain->pending_count >= MAX_TRANSACTIONS) {
        printf("Pending transaction limit reached\n");
        return 0;
    }
     if (strcmp(sender, "SYSTEM") != 0) {
        double sender_balance = get_balance(blockchain, sender);
        if (sender_balance < amount) {
            printf("Insufficient funds for %s (Balance: %.2f, Required: %.2f)\n", sender, sender_balance, amount);
            return 0;
        }
    }

    Transaction tx;
    strncpy(tx.sender, sender, 99);
    strncpy(tx.recipient, recipient, 99);
    tx.amount = amount;
    tx.timestamp = time(NULL);

    blockchain->pending_transactions[blockchain->pending_count++] = tx;

    printf("Transaction added: %s -> %s: %.2f\n", sender, recipient, amount);
    return 1;
}


Block *get_latest_block(Blockchain *blockchain) {
    return &blockchain->blocks[blockchain->size - 1];
}

void mine_pending_transactions(Blockchain *blockchain, const char *miner_address) {
    printf("Mining new block...\n");

    Block new_block;
    new_block.index = blockchain->size;
    new_block.transaction_count = blockchain->pending_count;

    for (int i = 0; i < blockchain->pending_count; i++) {
        new_block.transactions[i] = blockchain->pending_transactions[i];
    }

    new_block.timestamp = time(NULL);
    strcpy(new_block.previous_hash, get_latest_block(blockchain)->hash);
    new_block.nonce = 0;

    mine_block(&new_block, blockchain->difficulty);

    blockchain->blocks[blockchain->size++] = new_block;
    blockchain->pending_count = 0;

    add_transaction(blockchain, "SYSTEM", miner_address, blockchain->mining_reward);

    printf("Block mined and added to blockchain\n");
}

int is_chain_valid(Blockchain *blockchain) {
    for (int i = 1; i < blockchain->size; i++) {
        Block *current = &blockchain->blocks[i];
        Block *previous = &blockchain->blocks[i - 1];

        char recalculated[HASH_SIZE];
        calculate_hash(current, recalculated);

        if (strcmp(current->hash, recalculated) != 0) {
            printf("Invalid hash at block %d\n", i);
            return 0;
        }

        if (strcmp(current->previous_hash, previous->hash) != 0) {
            printf("Invalid chain link at block %d\n", i);
            return 0;
        }
    }
    return 1;
}

void print_block(Block *block) {
    printf("Block #%d\n", block->index);
    printf("Timestamp: %ld\n", block->timestamp);
    printf("Previous Hash: %s\n", block->previous_hash);
    printf("Hash: %s\n", block->hash);
    printf("Nonce: %d\n", block->nonce);
    printf("Transactions (%d):\n", block->transaction_count);
    for (int i = 0; i < block->transaction_count; i++) {
        Transaction *tx = &block->transactions[i];
        printf("  %s -> %s: %.2f\n", tx->sender, tx->recipient, tx->amount);
    }
    printf("\n");
}

void print_blockchain(Blockchain *blockchain) {
    printf("\n===== BLOCKCHAIN =====\n");
    for (int i = 0; i < blockchain->size; i++) {
        print_block(&blockchain->blocks[i]);
    }
    printf("======================\n");
}

void check_wallet_balance(Blockchain *blockchain) {
    char wallet[100];
    printf("Enter wallet address: ");
    fgets(wallet, sizeof(wallet), stdin);
    wallet[strcspn(wallet, "\n")] = 0; // Remove newline

    double balance = get_balance(blockchain, wallet);
    printf("Balance for %s: %.2f\n", wallet, balance);
}

void list_known_wallets(Blockchain *blockchain) {
    char wallets[BLOCKCHAIN_SIZE * MAX_TRANSACTIONS * 2][100];  // worst-case size
    int wallet_count = 0;

    for (int i = 0; i < blockchain->size; i++) {
        Block *block = &blockchain->blocks[i];

        for (int j = 0; j < block->transaction_count; j++) {
            Transaction *tx = &block->transactions[j];

            // Check sender
            int sender_exists = 0;
            for (int k = 0; k < wallet_count; k++) {
                if (strcmp(wallets[k], tx->sender) == 0) {
                    sender_exists = 1;
                    break;
                }
            }
            if (!sender_exists) {
                strncpy(wallets[wallet_count++], tx->sender, 99);
            }

            // Check recipient
            int recipient_exists = 0;
            for (int k = 0; k < wallet_count; k++) {
                if (strcmp(wallets[k], tx->recipient) == 0) {
                    recipient_exists = 1;
                    break;
                }
            }
            if (!recipient_exists) {
                strncpy(wallets[wallet_count++], tx->recipient, 99);
            }
        }
    }

    printf("\nKnown Wallet Addresses:\n");
    for (int i = 0; i < wallet_count; i++) {
        printf(" - %s\n", wallets[i]);
    }
}


// Updated main() function as discussed
    int main() {
    Blockchain blockchain;
    init_blockchain(&blockchain);

    int choice;
    char sender[100], recipient[100];
    double amount;
    char miner_address[100];

    while (1) {
        printf("\n===== BLOCKCHAIN MENU =====\n");
        printf("1. Add Transaction\n");
        printf("2. Mine Block\n");
        printf("3. Print Blockchain\n");
        printf("4. Validate Blockchain\n");
        printf("5. Exit\n");
        printf("6. Check Balance\n");
        printf("7. List Known Wallets\n");
        printf("Enter your choice: ");
        scanf("%d", &choice);
        getchar(); // clear newline

        switch (choice) {
            case 1:
                printf("Enter sender: ");
                fgets(sender, sizeof(sender), stdin);
                sender[strcspn(sender, "\n")] = 0; // remove newline

                printf("Enter recipient: ");
                fgets(recipient, sizeof(recipient), stdin);
                recipient[strcspn(recipient, "\n")] = 0;

                printf("Enter amount: ");
                scanf("%lf", &amount);
                getchar();

                add_transaction(&blockchain, sender, recipient, amount);
                break;

            case 2:
                printf("Enter miner address: ");
                fgets(miner_address, sizeof(miner_address), stdin);
                miner_address[strcspn(miner_address, "\n")] = 0;

                mine_pending_transactions(&blockchain, miner_address);
                break;

            case 3:
                print_blockchain(&blockchain);
                break;

            case 4:
                if (is_chain_valid(&blockchain)) {
                    printf("Blockchain is valid!\n");
                } else {
                    printf("Blockchain is invalid!\n");
                }
                break;

            case 5:
                printf("Exiting...\n");
                return 0;
                break;
            case 6:
                check_wallet_balance(&blockchain);
                break;
            case 7:
                list_known_wallets(&blockchain);
                break;
            default:
                printf("Invalid choice. Try again.\n");
        }
    }

    return 0;\
}


