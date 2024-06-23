use crate::button;
use crate::button::{ButtonColor, ButtonState, PrivaxyButton};
use crate::filters::{AddFilterRequest, Filter, FilterConfiguration, FilterGroup};
use crate::save_button::BASE_BUTTON_CSS;
use crate::{save_button, submit_banner};
use filterlists_api;
use reqwasm::http::Request;
use url::Url;
use wasm_bindgen_futures::spawn_local;
use web_sys::HtmlInputElement;
use yew::prelude::*;
use yew::InputEvent;
use yew::{html, Component, Context, Html};
pub enum SearchFilterMessage {
    Open,
    Close,
    FilterChanged(String),
    AddFilter(filterlists_api::Filter),
    RemoveFilter(filterlists_api::Filter),
    LoadFilters,
    FiltersLoaded(Vec<filterlists_api::Filter>),
    Error(String),
    NextPage,
    PreviousPage,
    LanguagesLoaded(Vec<filterlists_api::FilterLanguage>),
    LicensesLoaded(Vec<filterlists_api::FilterLicense>),
    TagsLoaded(Vec<filterlists_api::FilterTag>),
}

pub struct SearchFilterList {
    link: yew::html::Scope<Self>,
    is_open: bool,
    filters: Vec<filterlists_api::Filter>,
    filter_query: String,
    loading: bool,
    languages: Vec<filterlists_api::FilterLanguage>,
    licenses: Vec<filterlists_api::FilterLicense>,
    tags: Vec<filterlists_api::FilterTag>,
    current_page: usize,
    results_per_page: usize,
    active_filters: FilterConfiguration,
}

const FILTER_TAG_GROUPS: [&'static str; 4] = ["ads", "privacy", "malware", "social"];

#[derive(Properties, PartialEq)]
pub struct Props {
    pub filter_configuration: FilterConfiguration,
}

impl Component for SearchFilterList {
    type Message = SearchFilterMessage;
    type Properties = Props;

    fn create(_ctx: &Context<Self>) -> Self {
        Self {
            link: _ctx.link().clone(),
            is_open: false,
            filters: Vec::<filterlists_api::Filter>::new(),
            languages: Vec::<filterlists_api::FilterLanguage>::new(),
            licenses: Vec::<filterlists_api::FilterLicense>::new(),
            tags: Vec::<filterlists_api::FilterTag>::new(),
            filter_query: String::new(),
            loading: true,
            current_page: 1,
            results_per_page: 10,
            active_filters: _ctx.props().filter_configuration.clone(),
        }
    }

    fn update(&mut self, _ctx: &Context<Self>, msg: SearchFilterMessage) -> bool {
        match msg {
            SearchFilterMessage::Open => {
                self.is_open = true;
                self.link.send_message(SearchFilterMessage::LoadFilters);
            }
            SearchFilterMessage::Close => self.is_open = false,
            SearchFilterMessage::FilterChanged(query) => self.filter_query = query,
            SearchFilterMessage::AddFilter(filter) => {
                let parsed_url =
                    match Url::parse(&filter.primary_view_url.clone().unwrap_or_default()) {
                        Ok(url) => url,
                        Err(err) => {
                            log::error!("Failed to parse URL: {}", err);
                            return false;
                        }
                    };
                let group: FilterGroup = self
                    .tags
                    .clone()
                    .into_iter()
                    .filter(|tag| {
                        filter.tag_ids.contains(&tag.id)
                            && FILTER_TAG_GROUPS.contains(&tag.name.as_str())
                    })
                    .map(|tag| match tag.name.as_str() {
                        "ads" => FilterGroup::Ads,
                        "privacy" => FilterGroup::Privacy,
                        "malware" => FilterGroup::Malware,
                        "social" => FilterGroup::Social,
                        _ => FilterGroup::Regional,
                    })
                    .next()
                    .unwrap_or(FilterGroup::Regional);

                let request_body: AddFilterRequest =
                    AddFilterRequest::new(filter.name.clone(), group, parsed_url);
                let request = Request::post("/api/filters")
                    .header("Content-Type", "application/json")
                    .body(serde_json::to_string(&request_body).unwrap());
                self.active_filters.push(Filter::new(
                    filter.name.clone(),
                    FilterGroup::Malware,
                    "".to_string(),
                ));
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
                })
            }
            SearchFilterMessage::RemoveFilter(filter) => {
                let parsed_url = match Url::parse(&filter.primary_view_url.clone().unwrap()) {
                    Ok(url) => url,
                    Err(err) => {
                        log::error!("Failed to parse URL: {}", err);
                        return false;
                    }
                };
                let request_body: AddFilterRequest =
                    AddFilterRequest::new(filter.name.clone(), FilterGroup::Malware, parsed_url);
                let request = Request::delete("/api/filters")
                    .header("Content-Type", "application/json")
                    .body(serde_json::to_string(&request_body).unwrap());
                spawn_local(async move {
                    match request.send().await {
                        Ok(response) => {
                            if response.ok() {
                                log::info!("Filter removed successfully");
                            } else {
                                log::error!("Failed to remove filter: {:?}", response.status());
                            }
                        }
                        Err(err) => {
                            log::error!("Request error: {:?}", err);
                        }
                    }
                })
            }
            SearchFilterMessage::LoadFilters => {
                if self.loading {
                    let link = self.link.clone();
                    spawn_local(async move {
                        let request = Request::get("/api/filterlists/list");
                        match request.send().await {
                            Ok(response) => {
                                if response.ok() {
                                    if let Ok(filters) =
                                        response.json::<Vec<filterlists_api::Filter>>().await
                                    {
                                        link.send_message(SearchFilterMessage::FiltersLoaded(
                                            filters,
                                        ))
                                    }
                                } else {
                                    log::error!("Failed to load filters: {:?}", response.status());
                                    link.send_message(SearchFilterMessage::Error(
                                        response.status().to_string(),
                                    ))
                                }
                            }
                            Err(err) => {
                                link.send_message(SearchFilterMessage::Error(err.to_string()))
                            }
                        }
                        let request = Request::get("/api/filterlists/languages");
                        match request.send().await {
                            Ok(response) => {
                                if response.ok() {
                                    if let Ok(langs) = response
                                        .json::<Vec<filterlists_api::FilterLanguage>>()
                                        .await
                                    {
                                        link.send_message(SearchFilterMessage::LanguagesLoaded(
                                            langs,
                                        ))
                                    }
                                } else {
                                    log::error!(
                                        "Failed to load languages: {:?}",
                                        response.status()
                                    );
                                    link.send_message(SearchFilterMessage::Error(
                                        response.status().to_string(),
                                    ))
                                }
                            }
                            Err(err) => {
                                link.send_message(SearchFilterMessage::Error(err.to_string()))
                            }
                        };
                        let request = Request::get("/api/filterlists/licenses");
                        match request.send().await {
                            Ok(response) => {
                                if response.ok() {
                                    if let Ok(licenses) =
                                        response.json::<Vec<filterlists_api::FilterLicense>>().await
                                    {
                                        link.send_message(SearchFilterMessage::LicensesLoaded(
                                            licenses,
                                        ))
                                    }
                                } else {
                                    log::error!("Failed to load licenses: {:?}", response.status());
                                    link.send_message(SearchFilterMessage::Error(
                                        response.status().to_string(),
                                    ))
                                }
                            }
                            Err(err) => {
                                link.send_message(SearchFilterMessage::Error(err.to_string()))
                            }
                        };
                        let request = Request::get("/api/filterlists/tags");
                        match request.send().await {
                            Ok(response) => {
                                if response.ok() {
                                    if let Ok(tags) =
                                        response.json::<Vec<filterlists_api::FilterTag>>().await
                                    {
                                        link.send_message(SearchFilterMessage::TagsLoaded(tags))
                                    }
                                } else {
                                    log::error!("Failed to load tags: {:?}", response.status());
                                    link.send_message(SearchFilterMessage::Error(
                                        response.status().to_string(),
                                    ))
                                }
                            }
                            Err(err) => {
                                link.send_message(SearchFilterMessage::Error(err.to_string()))
                            }
                        };
                    });
                }
            }
            SearchFilterMessage::FiltersLoaded(filters) => {
                log::info!("Filters loaded successfully");
                self.filters = filters.clone();
                self.loading = false;
            }
            SearchFilterMessage::LanguagesLoaded(langs) => {
                log::info!("Languages loaded successfully");
                self.languages = langs.clone();
            }
            SearchFilterMessage::LicensesLoaded(licenses) => {
                log::info!("Licenses loaded successfully");
                self.licenses = licenses.clone();
            }
            SearchFilterMessage::TagsLoaded(tags) => {
                log::info!("Tags loaded successfully");
                self.tags = tags.clone();
            }
            SearchFilterMessage::Error(error) => {
                log::error!("Error loading filters: {}", error.to_string());
                self.loading = false;
            }
            SearchFilterMessage::NextPage => {
                if self.current_page
                    < (self.filters.len() as f64 / self.results_per_page as f64).ceil() as usize
                {
                    self.current_page += 1;
                }
            }
            SearchFilterMessage::PreviousPage => {
                if self.current_page > 1 {
                    self.current_page -= 1;
                }
            }
        }
        true
    }

    fn view(&self, _ctx: &Context<Self>) -> Html {
        let filtered_filters: Vec<&filterlists_api::Filter> = self
            .filters
            .iter()
            .filter(|filter| {
                filter
                    .name
                    .to_lowercase()
                    .contains(&self.filter_query.to_lowercase())
            })
            .collect();
        let total_pages =
            (filtered_filters.len() as f64 / self.results_per_page as f64).ceil() as usize;
        let start_index = (self.current_page - 1) * self.results_per_page;
        let paginated_filters = filtered_filters
            .into_iter()
            .skip(start_index)
            .take(self.results_per_page);

        let prev_button = html! {
        <PrivaxyButton
            color={ButtonColor::Gray}
            state={if self.current_page == 1 {ButtonState::Disabled} else {ButtonState::Enabled}}
            onclick={self.link.callback(|_| SearchFilterMessage::PreviousPage)}
            button_text={"Previous"}
        />
        };
        let next_button = html! {
        <PrivaxyButton
            color={ButtonColor::Gray}
            state={if self.current_page == total_pages {ButtonState::Disabled} else {ButtonState::Enabled}}
            onclick={self.link.callback(|_| SearchFilterMessage::NextPage)}
            button_text={"Next"}
        />
        };
        let search_logo_svg = html! {
            <svg xmlns="http://www.w3.org/2000/svg" class="-ml-0.5 mr-2 h-5 w-5" fill="none" viewBox="0 0 490.4 490.4" stroke="currentColor">
                    <path fill="white" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M484.1,454.796l-110.5-110.6c29.8-36.3,47.6-82.8,47.6-133.4c0-116.3-94.3-210.6-210.6-210.6S0,94.496,0,210.796 s94.3,210.6,210.6,210.6c50.8,0,97.4-18,133.8-48l110.5,110.5c12.9,11.8,25,4.2,29.2,0C492.5,475.596,492.5,463.096,484.1,454.796z M41.1,210.796c0-93.6,75.9-169.5,169.5-169.5s169.6,75.9,169.6,169.5s-75.9,169.5-169.5,169.5S41.1,304.396,41.1,210.796z"/>
                </svg>
        };

        let cancel_button = html! {
            <div class="flex space-x-4">
            <PrivaxyButton
                state={ButtonState::Enabled}
                onclick={self.link.callback(|_| SearchFilterMessage::Close)}
                color={ButtonColor::Red}
                button_text={"Cancel"}
            />
            </div>
        };

        let search_button = html! {
            <div class="mt-5">
            <PrivaxyButton
                state={ButtonState::Enabled}
                onclick={self.link.callback(|_| SearchFilterMessage::Open)}
                color={ButtonColor::Blue}
                button_text={"Search filterlists.com"}
                children={search_logo_svg}
            />
            </div>

        };
        let document = gloo_utils::document();
        if let Some(body) = document.body() {
            body.set_class_name(if self.is_open { "modal-open" } else { "" });
        }

        html! {
            <>
            {search_button}
                { if self.is_open {
                    html! {
                        <div class="fixed inset-0 bg-gray-600 bg-opacity-75 flex items-center justify-center z-50">
                            <div class="bg-white p-6 rounded-lg shadow-lg z-60" style="width: 50vw; height: 80vh; overflow: hidden;">
                                <div class="flex flex-col space-y-4" style="height: 100%;">
                                    <input type="text" placeholder="Search by name" class="border border-gray-300 p-2 rounded"
                                        value={self.filter_query.clone()}
                                        oninput={_ctx.link().callback(|e: InputEvent| {
                                            let input = e.target_dyn_into::<HtmlInputElement>().expect("input element");
                                            SearchFilterMessage::FilterChanged(input.value())
                                        })}
                                    />
                                    <div style="flex-grow: 1; overflow: auto;">
                                        <table class="table-fixed bg-white">
                                            <thead>
                                                <tr style="height: 5vh;">
                                                    <th class="py-2" style="width: 5vw;">{"Name"}</th>
                                                    <th class="py-2" style="width: 10vw;">{"Description"}</th>
                                                    <th class="py-2" style="width: 8vw;">{"Language"}</th>
                                                    <th class="py-2" style="width: 8vw;">{"License"}</th>
                                                    <th class="py-2" style="width: 2vw;">{"Select"}</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                { for paginated_filters.map(|filter| self.view_filter_row(filter, _ctx)) }
                                            </tbody>
                                        </table>
                                    </div>
                                    <div class="flex justify-between mt-4">
                                        {prev_button}
                                        <span>{"Page "} {self.current_page} {" of "} {total_pages}</span>
                                       {next_button}
                                    </div>
                                    {cancel_button}
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

impl SearchFilterList {
    fn view_filter_row(&self, filter: &filterlists_api::Filter, ctx: &Context<Self>) -> Html {
        let filter_clone = filter.clone();
        let existing_filter = self
            .active_filters
            .clone()
            .into_iter()
            .any(|f| f.title == filter.name);
        let button = if existing_filter {
            html! {
                <PrivaxyButton state={ButtonState::Enabled} onclick={ctx.link().callback(move |_| SearchFilterMessage::RemoveFilter(filter_clone.clone()))} color={ButtonColor::Red} button_text={"Remove"}/>
            }
        } else {
            html! {
                <PrivaxyButton state={ButtonState::Enabled} onclick={ctx.link().callback(move |_| SearchFilterMessage::AddFilter(filter_clone.clone()))} color={ButtonColor::Green} button_text={"Add"}/>
            }
        };
        html! {
            <tr>
                <td class="border px-4 py-2 overflow-hidden" style="height: 5vh; white-space: normal; text-overflow: ellipsis;">
                    { if let Some(url) = &filter.primary_view_url {
                        html! { <a href={url.clone()} target="_blank" class="text-blue-600 underline"> { &filter.name } </a> }
                    } else {
                        html! { &filter.name }
                    }}
                </td>
                <td class="border px-4 py-2 overflow-auto" style="height: 5vh; max-width: 10vw; white-space: normal;">
                    { &filter.description.clone().unwrap_or_default() }
                </td>
                <td class="border px-4 py-2 overflow-hidden" style="height: 5vh; white-space: nowrap; text-overflow: ellipsis;">
                    { self.get_language_name(filter.language_ids.clone()) }
                </td>
                <td class="border px-4 py-2 overflow-hidden" style="height: 5vh; white-space: nowrap; text-overflow: ellipsis;">
                    { self.get_license_name(filter.license_id) }
                </td>
                <td class="border px-4 py-2 text-center overflow-hidden" style="height: 5vh; white-space: nowrap; text-overflow: ellipsis;">
                { button }
                </td>
            </tr>
        }
    }

    fn get_language_name(&self, language_ids: Vec<u32>) -> String {
        self.languages
            .iter()
            .filter(|lang| language_ids.contains(&lang.id))
            .map(|lang| lang.name.clone())
            .collect::<Vec<String>>()
            .join(", ")
    }

    fn get_license_name(&self, license_id: u32) -> String {
        self.licenses
            .iter()
            .filter(|license| license.id == license_id)
            .map(|license| license.name.clone())
            .collect::<Vec<String>>()
            .join(", ")
    }
}
