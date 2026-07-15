#!/usr/bin/env python3

from __future__ import annotations

import abc
import functools

from dataclasses import dataclass, field
from typing import Type, List, Optional, Any

from costs import Budget, DEFAULT_BUDGET, STEP, ENV_EDGE, atom_scan
from element import Element, SExpr, Atom, Cons, Error, Func, FuncClass
from opcodes import SExpr_FUNCS, Op_FUNCS, Opcode
from workitem import fn_fin, fn_quote, fn_op, fn_partial

####

SpecialBLLOps = {
    'q': 0,
    'a': 1,
#    'sf': 2,
    'partial': 3,
}

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
    #elif opnum == 2:
    #    return fn_softfork()
    elif opnum == 3:
        return Func(fn_partial, None, Atom(0))
    else:
        opcls = Op_FUNCS.get(opnum, None)
        if opcls is None: return None
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
                if not workitem.budget.exhausted:
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
        if isinstance(value, Atom):
            opnum = value.as_int()
            value.deref()
            opcls = Op_FUNCS.get(opnum, None)
            if opcls is not None:
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
        if not self.budget.charge(STEP):
            return
        c = self.continuations.pop()
        fnobj, state = c.fn.steal_func()
        fnobj.step(state, c.args, c.env, self)

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

