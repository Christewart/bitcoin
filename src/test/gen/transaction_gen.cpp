#include <rapidcheck/gen/Arbitrary.h>
#include <rapidcheck/Gen.h>

#include "primitives/transaction.h" 
#include "script/script.h"
#include "amount.h"

#include "test/gen/transaction_gen.h"

namespace rc { 
  
  /** Generates one or more inputs */ 
  Gen<std::vector<CTxIn>> oneOrMoreInputs() {
    return gen::suchThat(gen::arbitrary<std::vector<CTxIn>>(), [](std::vector<CTxIn> vin) {
      return vin.size() > 0;      
    });
  }
    
  /** Generates one or more outputs */
  Gen<std::vector<CTxOut>> oneOrMoreOutputs() { 
    return gen::suchThat(gen::arbitrary<std::vector<CTxOut>>(), [](std::vector<CTxOut> vout) {
      return vout.size() > 0;      
    });
  }

}
