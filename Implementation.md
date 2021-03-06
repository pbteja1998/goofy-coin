## GoofyCoin – A Semi-Centralized Peer-to-Peer Electronic Cash System
### [Bhanu Teja P](https://github.com/pbteja1998)

## Rules:
- Only **Goofy** can create coins in this system. 
- Any node in the **GoofyChain network** can send **GoofyCoins** to any other node.

## Implementation
- The following operations can be performed in this system.
  - **Create New User/Node**
  - **Create CoinBase Transaction**
  - **Create Payment Transaction**
  - **Show Existing Users/Nodes**
  - **Show the Public Append Ledger in the human readable format**
  
- **Transaction Data Structure**
  - This data structure contains the following fields
  - **trx_id** – transaction id which is unique to each transaction
  - **sender** - sender’s public key
  - **receiver** - receiver’s public key
  - **trx_value** - number of coins that are being transacted in this transaction
  - **trx_timestamp** - timestamp at which the transaction occurred
  - **trx_type** - transaction type
    - **TRX_TYPE_PAY_COINS** - Coin Base Transaction
    - **TRX_TYPE_CREATE_COINS** - Payment Transaction
  - **spent** – A boolean flag to check if the coins in this transaction are spent
  - **prev_trx** - pointer to the previous transaction
  - **break_trx** - pointer to the transaction from which the coins are being transferred
  - **trx_message** - transaction message which is generated by concatenating all the above fields
  - **trx_hash** -  transaction hash generated using the above trx_message
  - **trx_signature** - transaction signature signed by the sender on the trx_hash generated above
  
- **Create New User**
  - **Username** is taken as input in order to create new user and is ensured to be unique.  
  - After taking the **username** as input, **public_key** and **private_key** are generated using **SHA256** and assigned to this newly created user.
  - **Public Key** is used to receive the coins and also used to  verify the transactions signed by the user.
  - **Private Key** is used to sign the transactions.
  
- **Create CoinBase Transaction**
  - CoinBase Transaction is a transaction where **Goofy Creates the Coins**.
  - **Number of Coins** is taken as input and then a transaction is generated which is signed by Goofy.
  - This transaction is then appended to the Public Append Ledger
  
- **Create Payment Transaction**
  - Payment Transaction is a transaction where one user/node sends some coins that he owned to another user/node.
  - **Sender S** and **Receiver R** ids are taken as input.
  - After that, **number of coins** is taken as input. Let us say number of coins in this transaction is **x**.
  - First we will check whether **Sender S** owns atleast **“x” number of coins** by traversing the blockchain.
  - While traversing the blockchain, in each transaction, first we will check if **Receiver Ri** in that transaction is **Sender S** in the current transaction. 
  - If so, we will then verify the signature of the transaction i.e., checking if the signature is indeed the signature of the **Sender Si** in that transaction.
  - If the signature is valid, then we will compare the number of coins in that transaction with **x**. Let us say that number of coins in that transaction is **y**.
  - If **y >= x**, then two transactions are created. (Let us call this type of transaction to be **TRX_A**)
    - One Transaction is **“S pays x number of coins to R”**. This will then be signed by **S**.
    - Another Transaction is **“S pays (y-x) number of coins to S”** (If **y-x == 0**, this transaction will not be created). This will then be signed by **S**.
    - The above two transactions will be appended to the **Public Append Ledger/BlockChain**.
    - The transaction in which **y** number of coins are present is marked as spent.
  - If **y < x**, then an atomic transaction is created.
    - **“S pays y number of coins to R”**. This transaction will then be signed by **S**.
    - The above transaction is added to the **Public Append Ledger/BlockChain**
    - **x = x – y**
    - continue traversing the blockchain till you find the transaction of type **TRX_A**
    
- **Show Existing Users/Nodes**
  - All existing nodes will be displayed with their **UserName** and **PublicKey**.
  
- **Show the Ledger/BlockChain in the human readable format.**
  - List of transactions will be shown.
  - For the payment type of transactions **back_pointer** will also be printed pointing to the **id** of the transaction from which the coins in present transaction are transferred.