
#include "breakpoints.h"


#include <stdio.h>
#include <stdlib.h>

#define INSN_IS_COMPRESSED(instr) ((instr & 0x3) != 0x3)
#define INSN_BP_COMPRESSED   0x8002
#define INSN_BP              0x00100073

BreakPoints::BreakPoints() {
 
  //m_cache = cache;
}

bool
BreakPoints::insert(unsigned int addr) {
  bool retval;
  uint32_t data_bp;
  struct bp_insn bp;

  bp.addr = addr;
  retval = dbg_axi_read32(addr + 4, (char*)&bp.insn_orig);
  
  bp.is_compressed = INSN_IS_COMPRESSED(bp.insn_orig);

  m_bp_list.push_back(bp);

  if (bp.is_compressed) {
    data_bp = INSN_BP_COMPRESSED;
    retval = retval && dbg_axi_write32(addr + 2, data_bp); 
  } else {
    data_bp = INSN_BP;
    retval = retval && dbg_axi_write32(addr + 4, data_bp);
  }

  return retval ;
}

bool
BreakPoints::remove(unsigned int addr) {

  bool retval;
  bool is_compressed;
  uint32_t data;
  for (std::list<struct bp_insn>::iterator it = m_bp_list.begin(); it != m_bp_list.end(); it++) {
    if (it->addr == addr) {
      data = it->insn_orig;
      is_compressed = it->is_compressed;

      m_bp_list.erase(it);

      if (is_compressed)
        retval = dbg_axi_write32(addr + 2, data);
      else
        retval = dbg_axi_write32(addr + 4, data);

      return retval ;
    }
  }

  return false;
}

bool
BreakPoints::clear() {

  bool retval = this->disable_all();

  m_bp_list.clear();

  return retval;
}


bool
BreakPoints::at_addr(unsigned int addr) {
  for (std::list<struct bp_insn>::iterator it = m_bp_list.begin(); it != m_bp_list.end(); it++) {
    if (it->addr == addr) {
      // we found our bp
      return true;
    }
  }

  return false;
}

bool
BreakPoints::enable(unsigned int addr) {
  bool retval;
  uint32_t data;

  for (std::list<struct bp_insn>::iterator it = m_bp_list.begin(); it != m_bp_list.end(); it++) {
    if (it->addr == addr) {
      if (it->is_compressed) {
        data = INSN_BP_COMPRESSED;
        retval = dbg_axi_write32(addr + 2, data);
       
      } else {
        data = INSN_BP;
        retval = dbg_axi_write32(addr + 4, data);
        
      }

      return retval && m_cache->flush();
    }
  }

  fprintf(stderr, "bp_enable: Did not find any bp at addr %08X\n", addr);

  return false;
}

bool
BreakPoints::disable(unsigned int addr) {
  bool retval;

  for (std::list<struct bp_insn>::iterator it = m_bp_list.begin(); it != m_bp_list.end(); it++) {
    if (it->addr == addr) {
      if (it->is_compressed)
        retval = dbg_axi_write32(addr + 2, it->insn_orig);
      else
        retval = dbg_axi_write32(addr + 4, it->insn_orig);

      return retval;
    }
  }

  fprintf(stderr, "bp_enable: Did not find any bp at addr %08X\n", addr);

  return false;
}

bool
BreakPoints::enable_all() {
  bool retval = true;

  for (std::list<struct bp_insn>::iterator it = m_bp_list.begin(); it != m_bp_list.end(); it++) {
    retval = retval && this->enable(it->addr);
  }

  return retval;
}

bool
BreakPoints::disable_all() {
  bool retval = true;

  for (std::list<struct bp_insn>::iterator it = m_bp_list.begin(); it != m_bp_list.end(); it++) {
    retval = retval && this->disable(it->addr);
  }

  return retval;
}
#include <stdio.h>
#include <stdlib.h>


#define INSN_IS_COMPRESSED(instr) ((instr & 0x3) != 0x3)
#define INSN_BP_COMPRESSED   0x8002
#define INSN_BP              0x00100073

BreakPoints::BreakPoints() {
 
  //m_cache = cache;
}

bool
BreakPoints::insert(unsigned int addr) {
  bool retval;
  uint32_t data_bp;
  struct bp_insn bp;

  bp.addr = addr;
  retval = dbg_axi_read32(addr + 4, (char*)&bp.insn_orig);
  
  bp.is_compressed = INSN_IS_COMPRESSED(bp.insn_orig);

  m_bp_list.push_back(bp);

  if (bp.is_compressed) {
    data_bp = INSN_BP_COMPRESSED;
    retval = retval && dbg_axi_write32(addr + 2, data_bp); 
  } else {
    data_bp = INSN_BP;
    retval = retval && dbg_axi_write32(addr + 4, data_bp);
  }

  return retval ;
}

bool
BreakPoints::remove(unsigned int addr) {

  bool retval;
  bool is_compressed;
  uint32_t data;
  for (std::list<struct bp_insn>::iterator it = m_bp_list.begin(); it != m_bp_list.end(); it++) {
    if (it->addr == addr) {
      data = it->insn_orig;
      is_compressed = it->is_compressed;

      m_bp_list.erase(it);

      if (is_compressed)
        retval = dbg_axi_write32(addr + 2, data);
      else
        retval = dbg_axi_write32(addr + 4, data);

      return retval ;
    }
  }

  return false;
}

bool
BreakPoints::clear() {

  bool retval = this->disable_all();

  m_bp_list.clear();

  return retval;
}


bool
BreakPoints::at_addr(unsigned int addr) {
  for (std::list<struct bp_insn>::iterator it = m_bp_list.begin(); it != m_bp_list.end(); it++) {
    if (it->addr == addr) {
      // we found our bp
      return true;
    }
  }

  return false;
}

bool
BreakPoints::enable(unsigned int addr) {
  bool retval;
  uint32_t data;

  for (std::list<struct bp_insn>::iterator it = m_bp_list.begin(); it != m_bp_list.end(); it++) {
    if (it->addr == addr) {
      if (it->is_compressed) {
        data = INSN_BP_COMPRESSED;
        retval = dbg_axi_write32(addr + 2, data);
       
      } else {
        data = INSN_BP;
        retval = dbg_axi_write32(addr + 4, data);
        
      }

      return retval && m_cache->flush();
    }
  }

  fprintf(stderr, "bp_enable: Did not find any bp at addr %08X\n", addr);

  return false;
}

bool
BreakPoints::disable(unsigned int addr) {
  bool retval;

  for (std::list<struct bp_insn>::iterator it = m_bp_list.begin(); it != m_bp_list.end(); it++) {
    if (it->addr == addr) {
      if (it->is_compressed)
        retval = dbg_axi_write32(addr + 2, it->insn_orig);
      else
        retval = dbg_axi_write32(addr + 4, it->insn_orig);

      return retval;
    }
  }

  fprintf(stderr, "bp_enable: Did not find any bp at addr %08X\n", addr);

  return false;
}

bool
BreakPoints::enable_all() {
  bool retval = true;

  for (std::list<struct bp_insn>::iterator it = m_bp_list.begin(); it != m_bp_list.end(); it++) {
    retval = retval && this->enable(it->addr);
  }

  return retval;
}

bool
BreakPoints::disable_all() {
  bool retval = true;

  for (std::list<struct bp_insn>::iterator it = m_bp_list.begin(); it != m_bp_list.end(); it++) {
    retval = retval && this->disable(it->addr);
  }

  return retval;
}
static bool
bp_insert(struct rsp_buf *buf) {
  enum mp_type type;
  uint32_t addr;
  uint32_t data_bp;
  int bp_len;

  if (3 != sscanf(buf->data, "Z%1d,%x,%1d", (int *)&type, &addr, &bp_len)) {
    fprintf(stderr, "Could not get three arguments\n");
    return false;
  }

  if (type != BP_MEMORY) {
    fprintf(stderr, "ERROR: Not a memory bp\n");
     put_str_packet ("");
    return false;
  }

  rsp.bp->insert(addr);

  return  put_str_packet ("OK");
}

static bool
bp_remove(struct rsp_buf *buf) {
  enum mp_type type;
  uint32_t addr;
  uint32_t ppc;
  int bp_len;
 

  if (3 != sscanf(buf->data, "z%1d,%x,%1d", (int *)&type, &addr, &bp_len)) {
    fprintf(stderr, "Could not get three arguments\n");
    return false;
  }

  if (type != BP_MEMORY) {
    fprintf(stderr, "Not a memory bp\n");
    return false;
  }

  rsp.bp->remove(addr);

  // check if we are currently on this bp that is removed
    dbg_axi_read32(DBG_PPC_REG, &ppc);
      

  if (addr == ppc) {
    dbg_axi_write32(DBG_NPC_REG, ppc); // re-execute this instruction
  }

   return  put_str_packet ("OK");
}