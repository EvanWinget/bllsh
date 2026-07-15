#!/usr/bin/env python3

from __future__ import annotations

import abc
import functools

from dataclasses import dataclass, field
from typing import Type, List, Optional, Any

from costs import Budget, DEFAULT_BUDGET, GUARD, STEP, ENV_EDGE, atom_scan
from element import Element, SExpr, Atom, Cons, Error, Func, FuncClass
from opcodes import SExpr_FUNCS, Op_FUNCS, Opcode, op_unknown, UNKNOWN_OP_RANGE
from workitem import fn_fin, fn_quote, fn_op, fn_partial

####

SpecialBLLOps = {
    'q': 0,
    'a': 1,
    'sf': 2,
    'partial': 3,
}

# The declared cost of a softfork guard must be a positive integer
# no wider than a signed 64 bit machine word. Any budget the system
# grants is far below this bound, so a wider declaration could never
# be paid and rejecting it keeps the decode within the machine
# integer fast path.
SOFTFORK_COST_MAX = 2**63 - 1

def ResolveOpcode(op : Element, budget : Budget) -> Optional[Func]:
    if not isinstance(op, Atom):
        return None
    # The operator decode skips non-minimal zero bytes, so a wide
    # operator atom charges its scan before it is read. A None return
    # with the budget exhausted means this charge failed, not that
    # the opcode is unknown.
    if not budget.charge(atom_scan(op.val1)):
        return None
    opnum = op.as_int()
    if opnum == 0:
        return Func(fn_quote, None, Atom(0))
    elif opnum == 1:
        return Func(fn_apply, None, Atom(0))
    elif opnum == 2:
        return Func(fn_softfork, None, Atom(0))
    elif opnum == 3:
        return Func(fn_partial, None, Atom(0))
    else:
        opcls = Op_FUNCS.get(opnum, None)
        if opcls is None:
            # Unassigned numbers inside the eligible range succeed as
            # unknown operators. Negative numbers and numbers at or
            # beyond UNKNOWN_OP_RANGE stay invalid opcodes.
            if 0 <= opnum < UNKNOWN_OP_RANGE:
                return Func(fn_op, (op_unknown, op_unknown.from_opnum(opnum)),
                            op_unknown.initial_state())
            return None
        return Func(fn_op, (opcls, opcls.initial_int_state()), opcls.initial_state())

def OpAtom(opcode : str) -> Optional[Atom]:
    if opcode in SpecialBLLOps:
        return Atom(SpecialBLLOps[opcode])
    elif opcode in SExpr_FUNCS:
        return Atom(SExpr_FUNCS[opcode])
    else:
        return None

####

def ResolveEnv(baseenv : Element, idx : int, budget : Budget) -> Optional[Element]:
    idxstart = idx
    env = baseenv
    while idx > 1:
        # Each tree edge is charged before it is checked, so an
        # invalid reference pays for the edge that discovered it. A
        # None return means the budget exhausted mid-walk.
        if not budget.charge(ENV_EDGE):
            env.deref()
            return None
        if not isinstance(env, Cons):
            env.deref()
            return Error(f"invalid env reference {idxstart} : {baseenv}")
        left, right = env.steal_children()
        if idx % 2 == 0:
            env = left
            right.deref()
        else:
            env = right
            left.deref()
        idx //= 2
    return env

#### allow specifying bll with named opcodes

def ToBLL(sexpr : Element) -> Element:
    assert isinstance(sexpr, Element)
    if sexpr.is_bll() or isinstance(sexpr, Error):
        return sexpr.bumpref()

    if sexpr.is_symbol():
        a = OpAtom(sexpr.val2)
        if a is None:
            return Error(f"unknown symbol {sexpr.val2}")
        else:
            return a

    if isinstance(sexpr, Cons):
        v1 = ToBLL(sexpr.val1)
        if isinstance(v1, Error):
            return v1
        v2 = ToBLL(sexpr.val2)
        if isinstance(v2, Error):
            v1.deref()
            return v2
        return Cons(v1, v2)

    return Error("cannot convert to bll")

#### evaluation model = workitem with continuations

@FuncClass.implements_API
class fn_blleval(FuncClass):
    @classmethod
    def step(cls, state : Element, args : Element, env : Any, workitem : Any) -> None:
        assert state.is_nil()
        state.deref()

        if not isinstance(args, Error) and not args.is_bll():
            # XXX should handle partial funcs here i guess?
            workitem.error(f"tried to eval something weird {args}")
            Element.deref_all(args, env)
            return

        if isinstance(args, Error):
            env.deref()
            workitem.fin_value(args)
        elif isinstance(args, Atom):
            # The positive-integer test and the environment walk both
            # read the whole atom, so a wide atom program charges its
            # scan first.
            if not workitem.budget.charge(atom_scan(args.val1)):
                Element.deref_all(args, env)
                return
            v = args.as_int()
            if v >= 1:
                envarg = ResolveEnv(env, v, workitem.budget)
                args.deref()
                if envarg is None:
                    # budget exhausted mid-walk
                    return
            else:
                envarg = args
                env.deref()
            workitem.fin_value(envarg)
        elif isinstance(args, Cons):
            op, args = args.steal_children()
            opfunc = ResolveOpcode(op, workitem.budget)
            if opfunc is None:
                Element.deref_all(args, env)
                # A None with the budget latched means the scan
                # charge failed, not that the opcode is unknown.
                if not workitem.budget.latched:
                    workitem.error(f"invalid opcode {op}")
            else:
                workitem.new_continuation(opfunc, args, env)
            op.deref()
        else:
            # internal error
            Element.deref_all(args, env)
            workitem.error("BUG? should be unreachable")

@FuncClass.implements_API
class fn_apply():
    # state structure:
    #   0 args: nil
    #   1 arg: Cons( nil, APPLY )
    #   2 args: Cons( 1, Cons( ENV, APPLY ) )

    @classmethod
    def step(cls, state : Element, args : Element, env : Any, workitem : Any) -> None:
        if args.is_nil():
            args.deref()
            if not isinstance(state, Cons):
                assert state.is_nil()
                apply_expr = state
                apply_env = env
            else:
                i, info = state.steal_children()
                if i.is_nil():
                    i.deref()
                    apply_expr = info
                    apply_env = env
                else:
                    assert isinstance(info, Cons)
                    assert i.is_atom() and i.val2 == b'\x01'
                    Element.deref_all(i, env)
                    apply_env, apply_expr = info.steal_children()
            workitem.eval_arg(apply_expr, apply_env)
        elif isinstance(args, Cons):
            arg, rest = args.steal_children()
            workitem.new_continuation(Func(cls, None, state), rest, env)
            workitem.eval_arg(arg, env.bumpref())
        else:
            workitem.error("argument to opcode is improper list")

    @classmethod
    def feedback(cls, state : Element, value : Element, args : Element, env : Any, workitem : Any) -> None:
        assert not isinstance(value, Error)

        if not isinstance(state, Cons):
            assert state.is_nil()
            newst = Cons(state, value)
        else:
            left, apply_el = state.steal_children()
            if left.is_nil():
                left.deref()
                newst = Cons(Atom(1), Cons(value, apply_el))
            else:
                Element.deref_all(left, apply_el, value, args, env)
                workitem.error("too many args to apply")
                return

        workitem.new_continuation(Func(cls, None, newst), args, env)

@FuncClass.implements_API
class fn_softfork(FuncClass):
    # state structure: the finished values as a plain list, newest
    # first, capped at five entries. The first four values are
    # stored, a fifth becomes a nil sentinel recording only that it
    # existed, and later values leave the state untouched, so the
    # list length is the arity saturated at five, enough to tell the
    # exactly-four shape from every other arity while the state stays
    # O(1) and allocation-free past the fifth argument whatever the
    # argument count.

    @classmethod
    def step(cls, state : Element, args : Element, env : Any, workitem : Any) -> None:
        if args.is_nil():
            args.deref()
            cls.finish(state, env, workitem)
        elif isinstance(args, Cons):
            arg, rest = args.steal_children()
            workitem.new_continuation(Func(cls, None, state), rest, env)
            workitem.eval_arg(arg, env.bumpref())
        else:
            Element.deref_all(state, args, env)
            workitem.error("argument to opcode is improper list")

    @classmethod
    def feedback(cls, state : Element, value : Element, args : Element, env : Any, workitem : Any) -> None:
        assert not isinstance(value, Error)
        # The bounded walk reads at most five links.
        stored = 0
        walk = state
        while isinstance(walk, Cons):
            stored += 1
            walk = walk.val2
        if stored < 4:
            newst = Cons(value, state)
        elif stored == 4:
            # Values beyond the fourth are evaluated and discarded:
            # any arity other than four charges the declared cost
            # and returns nil, so the state only records that a
            # fifth value existed, as a nil sentinel, and the value
            # itself is released rather than kept live to finish.
            value.deref()
            newst = Cons(Atom(0), state)
        else:
            value.deref()
            newst = state
        workitem.new_continuation(Func(cls, None, newst), args, env)

    @classmethod
    def finish(cls, state : Element, env : Any, workitem : Any) -> None:
        budget = workitem.budget
        if state.is_nil():
            Element.deref_all(state, env)
            workitem.error("softfork requires positive cost")
            return
        vals = []
        values = state
        while isinstance(values, Cons):
            v, values = values.steal_children()
            vals.append(v)
        values.deref()
        count = len(vals)
        vals.reverse()

        # The declared cost is hard validity: a wide atom charges its
        # scan before the read, and anything but a positive integer
        # within the machine word fails whatever the arity.
        cost_el = vals[0]
        declared = None
        if isinstance(cost_el, Atom):
            if not budget.charge(atom_scan(cost_el.val1)):
                Element.deref_all(*vals)
                env.deref()
                return
            v = cost_el.as_int()
            if 1 <= v <= SOFTFORK_COST_MAX:
                declared = v
        if declared is None:
            Element.deref_all(*vals)
            env.deref()
            workitem.error("softfork requires positive cost")
            return

        # The declared cost is charged as one lump whether or not a
        # guard runs, so every validator prices this application
        # identically however much of its form it understands.
        if not budget.charge(declared):
            Element.deref_all(*vals)
            env.deref()
            return

        # Everything from here is lenient: an unrecognized shape or
        # extension is the soft-fork hook and must stay valid, so it
        # delivers nil rather than failing.
        recognized = False
        if count == 4:
            ext = vals[1]
            if isinstance(ext, Atom):
                if not budget.charge(atom_scan(ext.val1)):
                    Element.deref_all(*vals)
                    env.deref()
                    return
                # Extension 0, the base operator table, is the only
                # extension recognized at launch.
                recognized = (ext.as_int() == 0)
        if not recognized:
            Element.deref_all(*vals)
            env.deref()
            workitem.fin_value(Atom(0))
            return

        program, guardenv = vals[2], vals[3]
        Element.deref_all(cost_el, vals[1], env)
        # The guarded program runs against an allowance of exactly
        # the declared cost, with the guard machinery's own flat
        # charge consumed out of it first.
        budget.push_allowance(declared)
        if not budget.charge(GUARD):
            Element.deref_all(program, guardenv)
            return
        workitem.new_continuation(Func(fn_exitguard, None, Atom(0)), Atom(0), Atom(0))
        workitem.eval_arg(program, guardenv)

@FuncClass.implements_API
class fn_exitguard(FuncClass):
    """The pending frame of an executing softfork guard. It receives
    the guarded program's value, discards it, and delivers nil if the
    guard's allowance was consumed exactly. An error raised inside
    the guard never reaches this frame, because the unwind discards
    the whole stack and clears the allowance."""

    @classmethod
    def step(cls, state : Element, args : Element, env : Any, workitem : Any) -> None:
        # The frame below a pending evaluation is only ever popped by
        # value delivery.
        Element.deref_all(state, args, env)
        workitem.error("BUG? should be unreachable")

    @classmethod
    def feedback(cls, state : Element, value : Element, args : Element, env : Any, workitem : Any) -> None:
        assert not isinstance(value, Error)
        Element.deref_all(state, value, args, env)
        if workitem.budget.pop_allowance():
            workitem.fin_value(Atom(0))
        else:
            workitem.error("softfork specified cost mismatch")

@dataclass
class Continuation:
    fn: Func
    args: Element           # (remaining) arguments to fn
    env: Element

    def __repr__(self):
        return f"Continuation({self.fn}, {self.args})"

    def deref(self):
        Element.deref_all(self.fn, self.args, self.env)

@dataclass
class WorkItem:
    continuations: List[Continuation]
    budget: Budget

    @classmethod
    def begin(cls, sexpr : Element, env : Element, budget : Optional[Budget] = None) -> WorkItem:
        if budget is None:
            budget = Budget(DEFAULT_BUDGET)
        wi = WorkItem(continuations=[], budget=budget)
        wi.eval_arg(sexpr, env)
        return wi

    def get_partial_func(self, value : Element) -> Optional[Element]:
        # Only table opcodes can be partially applied: the magic
        # operators and unknown operators are rejected through the
        # common None path, which owns the single deref of value.
        if isinstance(value, Atom):
            opnum = value.as_int()
            opcls = Op_FUNCS.get(opnum, None)
            if opcls is not None:
                value.deref()
                return Func(fn_op, (opcls, opcls.initial_int_state()), opcls.initial_state())
        elif isinstance(value, Func) and issubclass(value.val1[0], (fn_op, fn_partial)):
            return value

        value.deref()
        return None

    def new_continuation(self, fn : Func, args : Element, env : Element) -> None:
        self.continuations.append(Continuation(fn, args, env))

    def fin_value(self, value : Element) -> None:
        self.new_continuation(Func(fn_fin, None, Atom(0)), value, Atom(0))

    def eval_arg(self, args : Element, env : Element) -> None:
        self.new_continuation(Func(fn_blleval, None, Atom(0)), args, env)

    def error(self, msg : str) -> None:
        self.fin_value(Error(msg))

    def step(self) -> None:
        # One STEP per continuation pop, charged before the pop. A
        # failed charge leaves the frame in place for unwind.
        if self.budget.charge(STEP):
            c = self.continuations.pop()
            fnobj, state = c.fn.steal_func()
            fnobj.step(state, c.args, c.env, self)
        # A guard allowance breach anywhere inside the step means the
        # guarded program overran its declared cost. The guard and
        # all pending work are abandoned and the evaluation finishes
        # with the mismatch error, so drivers never see the breach
        # latch itself.
        if self.budget.guard_breach:
            self.unwind()
            self.fin_value(Error("softfork specified cost mismatch"))

    def feedback(self, value : Element) -> None:
        # An error discards the whole stack first, uncharged: every
        # discarded frame was paid for by the charge that popped or
        # pushed it. The final delivery to an empty stack is also
        # uncharged, only the pop that hands the value to a receiver
        # pays STEP.
        if isinstance(value, Error):
            self.unwind()

        if not self.continuations:
            self.fin_value(value)
            return

        if not self.budget.charge(STEP):
            value.deref()
            return

        c = self.continuations.pop()
        fnobj, state = c.fn.steal_func()
        fnobj.feedback(state, value, c.args, c.env, self)

    def finished(self) -> bool:
        return len(self.continuations) == 1 and self.continuations[0].fn.val1[0] == fn_fin

    def unwind(self) -> None:
        for c in self.continuations:
            c.deref()
        self.continuations = []
        # Abandoning pending work abandons any active guards with it.
        self.budget.clear_allowances()

    def get_result(self) -> Element:
        assert self.finished()
        r = self.continuations[0].args.bumpref()
        self.continuations.pop().deref()
        return r

def eval(sexpr : Element, globalenv : Element, budget : Optional[Budget] = None) -> Element:
    wi = WorkItem.begin(sexpr, globalenv, budget)

    while not wi.finished() and not wi.budget.exhausted:
        wi.step()

    if wi.budget.exhausted:
        wi.unwind()
        return Error("budget exhausted")

    return wi.get_result()

