//interface used to implement drivers for crypto modules

struct cryptomod_operations {
};

int cryptomod_register(char *name, struct cryptomod_operations *ops);
