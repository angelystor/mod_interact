%%%----------------------------------------------------------------------
%%% File    : mod_last.erl
%%% Author  : Alexey Shchepin <alexey@process-one.net>
%%% Purpose : jabber:iq:last support (XEP-0012)
%%% Created : 24 Oct 2003 by Alexey Shchepin <alexey@process-one.net>
%%%
%%%
%%% ejabberd, Copyright (C) 2002-2013   ProcessOne
%%%
%%% This program is free software; you can redistribute it and/or
%%% modify it under the terms of the GNU General Public License as
%%% published by the Free Software Foundation; either version 2 of the
%%% License, or (at your option) any later version.
%%%
%%% This program is distributed in the hope that it will be useful,
%%% but WITHOUT ANY WARRANTY; without even the implied warranty of
%%% MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
%%% General Public License for more details.
%%%
%%% You should have received a copy of the GNU General Public License
%%% along with this program; if not, write to the Free Software
%%% Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
%%% 02111-1307 USA
%%%
%%%----------------------------------------------------------------------

-module(mod_offline_iq).

-author('angelystor').

-behaviour(gen_mod).

-export([start/2, stop/1, process_sm_iq/3, process_local_iq/3, store_packet/3]).

-include("ejabberd.hrl").
-include("jlib.hrl").

-include("mod_privacy.hrl").

-define(NS_IQ_OOB, "jabber:iq:oob").

% cped from https://github.com/processone/exmpp/blob/master/include/exmpp_xml.hrl
-type(xmlname() :: atom() | string()).
-type(attributename() :: binary()).

-record(xmlattr, {
  ns = undefined   :: xmlname() | undefined,
  name             :: xmlname(),
  value            :: binary()
}).
-type(xmlattr() :: #xmlattr{}).

-record(xmlcdata, {
  cdata = <<>>     :: binary()
}).
-type(xmlcdata() :: #xmlcdata{}).

-record(xmlel, {
   ns = undefined   :: xmlname() | undefined,
   declared_ns = [] ,
   name             :: xmlname(),
   attrs = []       :: [xmlattr()],
   children = []    :: [#xmlel{} | xmlcdata()] | undefined
}).


start(Host, Opts) ->
    ?INFO_MSG("Starting mod offline iq ~p ~p", [?MODULE, ?NS_IQ_OOB]),

    IQDisc = gen_mod:get_opt(iqdisc, Opts, one_queue),
    %%% apparently we need to register this part, or the
    %%% handlers won't fire
    mod_disco:register_feature(Host, ?NS_IQ_OOB),    
    gen_iq_handler:add_iq_handler(ejabberd_sm, Host, ?NS_IQ_OOB, ?MODULE, process_sm_iq, IQDisc),
    gen_iq_handler:add_iq_handler(ejabberd_local, Host, ?NS_IQ_OOB, ?MODULE, process_local_iq, IQDisc),    

    ejabberd_hooks:add(offline_message_hook, Host, ?MODULE,
               store_packet, 50),
    ok.

stop(Host) ->
    ?INFO_MSG("Stopping mod offline iq", []),
    gen_iq_handler:remove_iq_handler(ejabberd_sm, Host, ?NS_IQ_OOB),
    gen_iq_handler:remove_iq_handler(ejabberd_local, Host, ?NS_IQ_OOB),
    ejabberd_hooks:delete(offline_message_hook, Host,
              ?MODULE, store_packet, 50),    
    ok.

store_packet(From, To, Packet) ->
    ?INFO_MSG("PACKET ~p", [Packet]).    

process_local_iq(From, _To,
     #iq{type = Type, sub_el = SubEl} = IQ) ->
     ?INFO_MSG("processing local iq ~p", [From]),

    done.

process_sm_iq(From, To,
        #iq{type = Type, sub_el = SubEl} = IQ) ->
    ?INFO_MSG("processing sm iq", []),
    case Type of 
      set ->
        User = To#jid.luser,
        Server = To#jid.lserver,

        ?INFO_MSG("set ~p ~p", [User, Server]),

        {Subscription, _Groups} = ejabberd_hooks:run_fold(roster_get_jid_info, 
                                                          Server,
                                                          {none, []}, 
                                                          [User, Server, From]),
        if (Subscription == both) or 
           (Subscription == from) or
           (From#jid.luser == To#jid.luser) and
           (From#jid.lserver == To#jid.lserver) ->

           UserListRecord = ejabberd_hooks:run_fold(privacy_get_user_list, 
                                                    Server,
                                                    #userlist{}, 
                                                    [User, Server]),
           case ejabberd_hooks:run_fold(privacy_check_packet,
                                        Server, 
                                        allow,
                                        [User, 
                                          Server, 
                                          UserListRecord,
                                          {To, From,
                                            #xmlel{name = <<"presence">>,
                                                   attrs = [],
                                                   children = []}},
                                          out])
               of
             allow -> 
              ?INFO_MSG("allowing iq to go to recipient ~p", [IQ]),
              ?INFO_MSG("#iq ~p", [#iq{type=Type, sub_el=[SubEl]}]),
              %ejabberd_router:route(From, To, jlib:iq_to_xml(#iq{type=Type, sub_el=[SubEl]})),
              IQ#iq{type = result, sub_el = [SubEl]};
             deny -> IQ#iq{type = error, sub_el = [SubEl, ?ERR_FORBIDDEN]}
           end;
           true -> IQ#iq{type = error, sub_el = [SubEl, ?ERR_FORBIDDEN]}
        end;




        %IQ#iq{type = result, sub_el = [SubEl]};        
      get ->
        User = To#jid.luser,
        Server = To#jid.lserver,
        ?INFO_MSG("user server ~p ~p", [User, Server]),
        IQ#iq{type = Type, sub_el = [SubEl]}

    end.
