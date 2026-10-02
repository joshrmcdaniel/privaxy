use crate::live_stream;
use futures::future::AbortHandle;
use serde::Deserialize;
use yew::{html, Component, Context, Html};

const MAX_REQUESTS_SHOWN: usize = 500;

#[derive(Deserialize)]
pub struct RequestEvent {
    now: String,
    method: String,
    url: String,
    is_request_blocked: bool,
}

pub enum Message {
    Received(RequestEvent),
    Connection(bool),
}

pub struct Requests {
    messages: Vec<RequestEvent>,
    connected: bool,
    ws_abort_handle: AbortHandle,
}

impl Component for Requests {
    type Message = Message;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        Self {
            ws_abort_handle: live_stream::subscribe(
                "/api/events",
                ctx.link().callback(Message::Received),
                ctx.link().callback(Message::Connection),
            ),
            messages: Vec::new(),
            connected: false,
        }
    }

    fn update(&mut self, _ctx: &Context<Self>, msg: Message) -> bool {
        match msg {
            Message::Received(event) => {
                self.messages.insert(0, event);
                self.messages.truncate(MAX_REQUESTS_SHOWN);
            }
            Message::Connection(connected) => self.connected = connected,
        }
        true
    }

    fn view(&self, _ctx: &Context<Self>) -> Html {
        fn render_element(element: &RequestEvent) -> Html {
            let background = {
                if element.is_request_blocked {
                    "bg-red-50"
                } else {
                    ""
                }
            };

            html! {

            <tr class={ background }>
                <td class="w-1/12 px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                    {&element.now}
                </td>
                <td class="w-1/12 px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    <span
                        class="inline-flex items-center px-2.5 py-0.5 rounded-md text-sm font-medium bg-blue-100 text-blue-800">
                        {&element.method}
                    </span>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {&element.url}
                </td>
            </tr>
                }
        }

        html! {
               <>
          <h3 class="text-2xl font-bold text-gray-900 pt-1.5">
            {"Requests feed"}
            if self.connected { <div class="mt-2 ml-3 inline pulsating-circle"></div> }
          </h3>
          if !self.connected {
              <p role="status" class="mt-2 text-sm text-gray-600">{"Connecting to requests feed… Retrying automatically."}</p>
          }
          <div class="mt-4 flex flex-col">
            <div class="-my-2 overflow-x-auto sm:-mx-6 lg:-mx-8">
              <div class="py-2 align-middle inline-block min-w-full sm:px-6 lg:px-8">
                <div class="shadow overflow-hidden border-b border-gray-200 sm:rounded-lg">
                  <table class="min-w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                      <tr>
                        <th scope="col"
                          class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          {"Timestamp"}
                        </th>
                        <th scope="col"
                          class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          {"Method"}
                        </th>
                        <th scope="col"
                          class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          {"Path"}
                        </th>
                      </tr>
                    </thead>
                    <tbody class="w-full bg-white divide-y divide-gray-200">
                      { for self.messages.iter().map(render_element) }
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>

        </>
               }
    }

    fn destroy(&mut self, _ctx: &Context<Self>) {
        self.ws_abort_handle.abort()
    }
}
