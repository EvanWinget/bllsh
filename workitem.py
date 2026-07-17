#!/usr/bin/env python3

from __future__ import annotations

import abc
import functools

from dataclasses import dataclass, field
from typing import Type, List, Optional, Any

from element import Element, SExpr, Atom, Cons, Error, Func, FuncClass
from opcodes import SExpr_FUNCS, Op_FUNCS, Opcode

####

@FuncClass.implements_API
class fn_fin(FuncClass):
    @classmethod
    def step(cls, state : Element, args : Element, env : Any, workitem : Any) -> None:
        assert state.is_nil()
        state.deref()
        env.deref()
        workitem.feedback(args)

@FuncClass.implements_API
class fn_quote(FuncClass):
    @classmethod
    def step(cls, state : Element, args : Element, env : Any, workitem : Any) -> None:
        assert state.is_nil()
        state.deref()
        env.deref()
        workitem.feedback(args)

@FuncClass.implements_API
class fn_op():
    def __init__(self, opcls : Type[Opcode], opintstate):
        self.opcls = opcls
        self.opintstate = opintstate

    def feed(self, state : Element, value : Element, budget) -> Optional[Element]:
        # XXX state/value should be handed over to the Opcode class
        (newst, newintst) = self.opcls.argument(budget, self.opintstate, state, value)
        Element.deref_all(state, value)
        if newst is None:
            # a charge failed mid-fold and latched the budget
            return None
        if isinstance(newst, Error):
            return newst
        else:
            return Func(self.__class__, (self.opcls, newintst), newst)

    @classmethod
    def getname(cls, opclsistate):
        opcls, opintstate = opclsistate
        name = opcls.__name__
        if opintstate is not None:
            name += ",**"
        return name

    def __repr__(self):
        return self.opcls.__name__

    def step(self, state : Element, args : Element, env : Any, workitem : Any) -> None:
        if args.is_nil():
            f = self.opcls.finish(workitem.budget, self.opintstate, state)  # XXX should consider state owned
            env.deref()
            Element.deref_all(state, args)
            if f is None:
                # a charge failed mid-finish and latched the budget
                return
            workitem.fin_value(f)
        elif isinstance(args, Cons):
            arg, rest = args.steal_children()
            workitem.new_continuation(Func(self.__class__, (self.opcls, self.opintstate), state), rest, env)
            workitem.eval_arg(arg, env.bumpref())
        else:
            env.deref()
            Element.deref_all(state, args)
            workitem.error("argument to opcode is improper list")

    def feedback(self, state : Element, value : Element, args : Element, env : Any, workitem : Any) -> None:
        assert not isinstance(value, Error)
        fed = self.feed(state, value, workitem.budget)
        if fed is None:
            Element.deref_all(args, env)
        elif isinstance(fed, Error):
            env.deref()
            args.deref()
            workitem.fin_value(fed)
        else:
            workitem.new_continuation(fed, args, env)

@FuncClass.implements_API
class fn_partial(FuncClass):
    @classmethod
    def step(cls, state : Element, args : Element, env : Any, workitem : Any) -> None:
        assert state.is_nil() or isinstance(state, Func)

        if args.is_nil():
            env.deref()
            args.deref()
            if state.is_nil():
                workitem.error("partial: requires opcode argument")
            else:
                workitem.fin_value(Func(cls, None, state))
        elif isinstance(args, Cons):
            arg, rest = args.steal_children()
            workitem.new_continuation(Func(cls, None, state), rest, env)
            workitem.eval_arg(arg, env.bumpref())
        else:
            env.deref()
            Element.deref_all(state, args)
            workitem.error("argument to partial is improper list")

    @classmethod
    def feedback(cls, state : Element, value : Element, args : Element, env : Any, workitem : Any) -> None:
        assert state.is_nil() or isinstance(state, Func)

        if state.is_nil():
            state.deref()
            value.bumpref()
            opfunc = workitem.get_partial_func(value)
            if opfunc is None:
                env.deref()
                args.deref()
                # A None with the budget latched means the decode's
                # scan charge failed, not that the value was rejected.
                if not workitem.budget.latched:
                    workitem.error(f"partial: requires a normal opcode as first argument not {value}")
                value.deref()
                return
            value.deref()

            assert isinstance(opfunc, Func)
            was_partial = issubclass(opfunc.val1[0], fn_partial)
            if was_partial:
                op = opfunc.val2.bumpref()
                opfunc.deref()
                opfunc = op
            assert issubclass(opfunc.val1[0], fn_op)
            if was_partial and args.is_nil():
                # finalise
                workitem.new_continuation(opfunc, args, env)
            else:
                workitem.new_continuation(Func(cls, None, opfunc), args, env)
        else:
            assert isinstance(state, Func) and issubclass(state.val1[0], fn_op)
            opobj, opstate = state.steal_func()
            nextfunc = opobj.feed(opstate, value, workitem.budget)
            if nextfunc is None:
                Element.deref_all(args, env)
                return
            if nextfunc.is_error():
                env.deref()
                args.deref()
                workitem.fin_value(nextfunc)
            else:
                workitem.new_continuation(Func(cls, None, nextfunc), args, env)

