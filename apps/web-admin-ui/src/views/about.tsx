import {
  ABOUT_PAGE_CONTENT,
  AboutPageLayout,
} from "@/content/about-content";

export function AboutView() {
  return (
    <div className="flex-1 h-full min-h-0 overflow-hidden">
      <div className="flex h-[640px] w-[748px]">
        <AboutPageLayout version={ABOUT_PAGE_CONTENT.defaultVersion} />
      </div>
    </div>
  );
}
