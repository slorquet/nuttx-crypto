//interface used to implement drivers for crypto modules

struct cryptomod_operations
{
  uint32_t dummy;
  //enum algs
  //find,store,delete key
  //cipher ops
  //ds ops
  //hash ops
  //derive,wrap,unwrap
  //genrandom
};

int cryptomod_register(char *name, struct cryptomod_operations *ops);
