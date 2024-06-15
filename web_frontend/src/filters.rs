use crate::filterlists::SearchFilterList;
use crate::{get_api_host, save_button, submit_banner};
use reqwasm::http::Request;
use serde::{Deserialize, Serialize};
use serde_json::de::IoRead;
use serde_json::StreamDeserializer;
use serde_with::{serde_as, DisplayFromStr};
use std::fmt::Debug;
use std::io::Cursor;
use url::Url;
use wasm_bindgen_futures::spawn_local;
use web_sys::{HtmlInputElement, HtmlSelectElement};
use yew::prelude::*;
use yew::InputEvent;
use yew::{html, Callback, Component, Context, Html};

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum FilterGroup {
    Default,
    Regional,
    Ads,
    Privacy,
    Malware,
    Social,
}

#[derive(Properties, PartialEq)]
pub struct Props {
    pub state: save_button::SaveButtonState,
}

impl FilterGroup {
    pub fn as_str(&self) -> &'static str {
        match self {
            FilterGroup::Default => "Default",
            FilterGroup::Regional => "Regional",
            FilterGroup::Ads => "Ads",
            FilterGroup::Privacy => "Privacy",
            FilterGroup::Malware => "Malware",
            FilterGroup::Social => "Social",
        }
    }

    pub fn values() -> Vec<Self> {
        vec![
            FilterGroup::Default,
            FilterGroup::Regional,
            FilterGroup::Ads,
            FilterGroup::Privacy,
            FilterGroup::Malware,
            FilterGroup::Social,
        ]
    }
}

pub enum AddFilterMessage {
    Open,
    Close,
    Save(String, String, FilterGroup),
    CategoryChanged(FilterGroup),
    UrlChanged(String),
    TitleChanged(String),
}

#[serde_as]
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct AddFilterRequest {
    enabled: bool,
    title: String,
    group: FilterGroup,
    #[serde_as(as = "DisplayFromStr")]
    url: Url,
}

impl AddFilterRequest {
    pub fn new(title: String, group: FilterGroup, url: Url) -> Self {
        Self {
            enabled: true,
            title,
            group,
            url,
        }
    }
}

pub struct AddFilterComponent {
    link: yew::html::Scope<Self>,
    is_open: bool,
    category: FilterGroup,
    title: String,
    url: String,
}

impl Component for AddFilterComponent {
    type Message = AddFilterMessage;
    type Properties = Props;

    fn create(_ctx: &Context<Self>) -> Self {
        Self {
            link: _ctx.link().clone(),
            is_open: false,
            category: FilterGroup::Default,
            url: String::new(),
            title: String::new(),
        }
    }

    fn update(&mut self, _ctx: &Context<Self>, msg: AddFilterMessage) -> bool {
        match msg {
            AddFilterMessage::Open => self.is_open = true,
            AddFilterMessage::Close => self.is_open = false,
            AddFilterMessage::Save(url, title, category) => {
                if let Ok(parsed_url) = Url::parse(&url) {
                    let request_body = AddFilterRequest {
                        enabled: true,
                        title: if title.is_empty() {
                            self.url.clone()
                        } else {
                            title
                        },
                        group: category,
                        url: parsed_url,
                    };

                    let request = Request::post("/api/filters")
                        .header("Content-Type", "application/json")
                        .body(serde_json::to_string(&request_body).unwrap());

                    spawn_local(async move {
                        match request.send().await {
                            Ok(response) => {
                                if response.ok() {
                                    log::info!("Filter added successfully");
                                } else {
                                    log::error!("Failed to add filter: {:?}", response.status());
                                }
                            }
                            Err(err) => {
                                log::error!("Request error: {:?}", err);
                            }
                        }
                    });
                } else {
                    log::error!("Invalid URL: {}", url);
                }
                self.is_open = false;
            }
            AddFilterMessage::CategoryChanged(category) => self.category = category,
            AddFilterMessage::UrlChanged(url) => self.url = url,
            AddFilterMessage::TitleChanged(title) => {
                self.title = title;
            }
        }
        true
    }

    fn view(&self, _ctx: &Context<Self>) -> Html {
        let mut save_button_classes = classes!(
            "inline-flex",
            "items-center",
            "justify-center",
            "focus:ring-green-500",
            "bg-green-600",
            "hover:bg-green-700",
            "px-4",
            "py-2",
            "border",
            "transition",
            "ease-in-out",
            "duration-150",
            "border-transparent",
            "text-sm",
            "font-medium",
            "rounded-md",
            "shadow-sm",
            "text-white",
            "focus:outline-none",
            "focus:ring-2",
            "focus:ring-offset-2",
            "focus:ring-offset-gray-100",
        );

        let properties = _ctx.props();

        if properties.state == save_button::SaveButtonState::Disabled
            || properties.state == save_button::SaveButtonState::Loading
        {
            save_button_classes.push("opacity-50");
            save_button_classes.push("cursor-not-allowed");
        }

        let button_text = if properties.state == save_button::SaveButtonState::Loading {
            "Loading..."
        } else {
            "Add filter"
        };

        let options: Html = FilterGroup::values()
            .into_iter()
            .map(|group| {
                html! {
                    <option value={group.as_str()}>{group.as_str()}</option>
                }
            })
            .collect();

        let url = self.url.clone();
        let category = self.category.clone();
        let title = self.title.clone();

        html! {
            <>
                <button onclick={self.link.callback(|_| AddFilterMessage::Open)} type="button" class={classes!(save_button_classes, "mt-5" )}>
                    <svg xmlns="http://www.w3.org/2000/svg" class="-ml-0.5 mr-2 h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
                    </svg>
                    {button_text}
                </button>
                {if self.is_open {
                    html! {
                        <div class="fixed inset-0 bg-gray-600 bg-opacity-75 flex items-center justify-center z-50 ">
                            <div class="bg-white p-6 rounded-lg shadow-lg z-60">
                                <div class="flex flex-col space-y-4">
                                    <div class="flex items-center">
                                        <div class="w-32">
                                            <label class="font-bold">{"Category"}</label>
                                        </div>
                                        <select class="flex-1 bg-white border border-gray-300 text-gray-700 py-2 px-4 pr-8 rounded leading-tight focus:outline-none focus:bg-white focus:border-gray-500"
                                            onchange={_ctx.link().callback(|e: Event| {
                                                let select = e.target_dyn_into::<HtmlSelectElement>().expect("event target should be a select element");
                                                let value = select.value();
                                                AddFilterMessage::CategoryChanged(FilterGroup::values().into_iter().find(|group| group.as_str() == value).expect("invalid category"))
                                            })}
                                        >
                                            { options }
                                        </select>
                                    </div>
                                    <div class="flex items-center">
                                        <div class="w-32">
                                            <label class="font-bold">{"Title"}</label>
                                        </div>
                                        <input
                                            type="text"
                                            class="flex-1 bg-white border border-gray-300 text-gray-700 py-2 px-4 rounded leading-tight focus:outline-none focus:bg-white focus:border-gray-500"
                                            value={self.title.clone()}
                                            oninput={_ctx.link().callback(|e: InputEvent| {
                                                let input = e.target_dyn_into::<HtmlInputElement>().expect("event target should be an input element");
                                                AddFilterMessage::TitleChanged(input.value())
                                            })}
                                        />
                                    </div>
                                    <div class="flex items-center">
                                        <div class="w-32">
                                            <label class="font-bold">{"EasyList URL"}</label>
                                        </div>
                                        <input
                                            type="text"
                                            class="flex-1 bg-white border border-gray-300 text-gray-700 py-2 px-4 rounded leading-tight focus:outline-none focus:bg-white focus:border-gray-500"
                                            value={self.url.clone()}
                                            oninput={_ctx.link().callback(|e: InputEvent| {
                                                let input = e.target_dyn_into::<HtmlInputElement>().expect("event target should be an input element");
                                                AddFilterMessage::UrlChanged(input.value())
                                            })}
                                        />
                                    </div>
                                    <div class="flex space-x-4">
                                        <button onclick={_ctx.link().callback(move |_| AddFilterMessage::Save(url.clone(), title.clone(), category.clone()))} class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded z-60">{"Save"}</button>
                                        <button onclick={_ctx.link().callback(|_| AddFilterMessage::Close)} class="bg-gray-500 hover:bg-gray-700 text-white font-bold py-2 px-4 rounded z-60">{"Cancel"}</button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    }
                } else {
                    html! {}
                }}
            </>
        }
    }
}

#[derive(Deserialize, Clone, PartialEq, Eq)]
pub struct Filter {
    enabled: bool,
    pub title: String,
    group: FilterGroup,
    file_name: String,
}

impl Filter {
    pub fn new(title: String, group: FilterGroup, file_name: String) -> Self {
        Self {
            enabled: true,
            title,
            group,
            file_name,
        }
    }
}

impl std::fmt::Display for Filter {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Filter(Enabled={}, Title={}, Group={:?}, File_name={})",
            self.enabled, self.title, self.group, self.file_name
        )
    }
}

#[allow(non_snake_case)]
#[derive(Serialize)]
pub struct FilterStatusChangeRequest {
    enabled: bool,
    file_name: String,
}

pub type FilterConfiguration = Vec<Filter>;

pub enum Message {
    Load,
    Display(FilterConfiguration),
    UpdateFilterSelection((String, bool)),
    Save,
    ChangesSaved,
}

pub struct Filters {
    filter_configuration: Option<FilterConfiguration>,
    filter_configuration_before_changes: Option<FilterConfiguration>,
    changes_saved: bool,
}

impl Filters {
    fn configuration_has_changed(&self) -> bool {
        self.filter_configuration != self.filter_configuration_before_changes
    }
    pub fn get_filters(&self) -> Vec<Filter> {
        self.filter_configuration.as_ref().unwrap().clone()
    }

    pub fn has_filter(&self, filter: &Filter) -> bool {
        self.filter_configuration
            .as_ref()
            .unwrap()
            .into_iter()
            .any(|f| f.file_name == filter.file_name)
    }
}

impl Component for Filters {
    type Message = Message;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        ctx.link().send_message(Message::Load);

        Self {
            filter_configuration: None,
            filter_configuration_before_changes: None,
            changes_saved: false,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Message::Display(filter_configuration) => {
                log::debug!("Displaying");
                self.filter_configuration = Some(filter_configuration.clone());
                self.filter_configuration_before_changes = Some(filter_configuration);
            }
            Message::Load => {
                log::debug!("Retrieving filters..");
                let request = Request::get("/api/filters");
                log::debug!("Request: {:?}", request);
                let message_callback = ctx.link().callback(|message: Message| message);
                log::debug!("Message callback: {:?}", message_callback);

                spawn_local(async move {
                    if let Ok(response) = request.send().await {
                        log::debug!("Response: {:?}", response);
                        if response.ok() {
                            log::debug!("Response OK");
                            if let Ok(body) = response.text().await {
                                let cursor = Cursor::new(body);
                                let stream = StreamDeserializer::new(IoRead::new(cursor));
                                for result in stream {
                                    match result {
                                        Ok(filter_configuration) => message_callback
                                            .emit(Message::Display(filter_configuration)),
                                        Err(e) => log::error!("Failed to parse chunk: {:?}", e),
                                    }
                                }
                            }
                        }
                    }
                });
            }
            Message::Save => {
                if !self.configuration_has_changed() {
                    return false;
                }
                let request_body = self
                    .filter_configuration
                    .as_ref()
                    .unwrap()
                    .iter()
                    .map(|filter| FilterStatusChangeRequest {
                        enabled: filter.enabled,
                        file_name: filter.file_name.clone(),
                    })
                    .collect::<Vec<_>>();

                let request = Request::put("/api/filters")
                    .header("Content-Type", "application/json")
                    .body(serde_json::to_string(&request_body).unwrap());

                let callback = ctx.link().callback(|message: Message| message);

                spawn_local(async move {
                    match request.send().await {
                        Ok(response) => {
                            if response.ok() {
                                callback.emit(Message::ChangesSaved);

                                return;
                            }
                        }
                        Err(_) => {}
                    }
                });

                log::info!("Save")
            }
            Message::UpdateFilterSelection((filter_name, enabled)) => {
                self.changes_saved = false;

                self.filter_configuration
                    .as_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|filter| filter.file_name == filter_name)
                    .and_then(|filter| {
                        filter.enabled = enabled;

                        Some(filter)
                    });
            }
            Message::ChangesSaved => {
                self.changes_saved = true;
                self.filter_configuration_before_changes = self.filter_configuration.clone();
            }
        };

        true
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        log::debug!("At view.");
        let save_button_state = if !self.configuration_has_changed() {
            save_button::SaveButtonState::Disabled
        } else {
            save_button::SaveButtonState::Enabled
        };
        log::debug!("Retrieving callback..");

        let callback = ctx
            .link()
            .callback(|(filter_file_name, enabled): (String, bool)| {
                Message::UpdateFilterSelection((filter_file_name, enabled))
            });
        log::debug!("Retrieved callback.");
        let save_callback = ctx.link().callback(|_| Message::Save);
        let render_category_filter = |filter: &Filter| {
            let filter_file_name = filter.file_name.clone();
            let filter_enabled = filter.enabled;
            let callback_clone = callback.clone();

            let checkbox_callback = Callback::from(move |_| {
                callback_clone.emit((filter_file_name.to_string(), !filter_enabled))
            });
            log::debug!("Returning category filter.");
            html! {
            <div class="relative flex items-start py-4">
                <div class="min-w-0 flex-1 text-sm">
                    <label for={filter.file_name.clone()} class="select-none">{&filter.title}</label>
                </div>
                <div class="ml-3 flex items-center h-5">
                    <input checked={filter.enabled} onchange={checkbox_callback} name={filter.file_name.clone()} type="checkbox"
                        class="focus:ring-blue-500 h-4 w-4 text-blue-600 border-gray-300 rounded" />
                </div>
            </div>
            }
        };
        log::debug!("Rendering category filter.");
        let render_category = |category: FilterGroup, filters: &FilterConfiguration| {
            let category_name = format!("{:?}", category);
            log::debug!("Category filter: {category_name}");
            let filters = filters
                .iter()
                .filter(|filter| filter.group == category)
                .collect::<Vec<_>>();

            log::debug!("Getting request body");
            log::debug!(
                "Filter self: {:?}",
                filters
                    .clone()
                    .into_iter()
                    .map(|i| i.to_string())
                    .collect::<String>()
            );
            html! {
            <fieldset class="mb-8">
                <legend class="text-lg font-medium text-gray-900">{category_name}</legend>
                <div class="mt-4 border-t border-b border-gray-200 divide-y divide-gray-200">
                    { for filters.into_iter().map(render_category_filter) }
                </div>
            </fieldset>
            }
        };

        let success_banner = if self.changes_saved {
            let icon = html! {
                <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-white" fill="none"
                    viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                        d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
            };
            html! {
                <submit_banner::SubmitBanner message="Changes saved" {icon} color={submit_banner::Color::Green}/>
            }
        } else {
            html! {}
        };

        let title = html! {
            <div class="pt-1.5 mb-4">
                <h1 class="text-2xl font-bold text-gray-900">{ "Filters" }</h1>
            </div>
        };

        match &self.filter_configuration {
            Some(filter_configuration) => {
                html! {
                        <>
                            { title }
                            {success_banner}
                            <div class="mb-5 flex space-x-4">
                                <AddFilterComponent state={save_button::SaveButtonState::Enabled}/>
                                <SearchFilterList filter_configuration={filter_configuration.clone()}/>
                                <save_button::SaveButton state={save_button_state} onclick={save_callback} />
                            </div>
                            { render_category(FilterGroup::Default, filter_configuration) }
                            { render_category(FilterGroup::Ads, filter_configuration) }
                            { render_category(FilterGroup::Privacy, filter_configuration) }
                            { render_category(FilterGroup::Malware, filter_configuration) }
                            { render_category(FilterGroup::Social, filter_configuration) }
                            { render_category(FilterGroup::Regional, filter_configuration) }
                        </>
                }
            }
            // This realistically loads way too fast for a loader to be useful. Adding one would just add
            // unwanted flickering.
            None => html! {{ title }},
        }
    }
}
