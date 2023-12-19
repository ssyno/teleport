/**
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

// Should be kept in sync with
// https://github.com/gravitational/teleport/blob/cc330931e2b691b7438bfee73587e828e874fa47/api/proto/teleport/userpreferences/v1/unified_resource_preferences.proto
//
// The exported enums and types have the same names and values/properties as
// the values generated by protogen.
// It allows using them interchangeably with the generated values.
//
// Ideally, we should use the generated values, but it was a challenge
// to make them work with Vite (the generated files are in CommonJS format);
// additionally, they increased the bundle size significantly.

/** Preferences related to the Unified Resource view. */
export interface UnifiedResourcePreferences {
  /** Default tab selected in the unified resource view. */
  defaultTab: DefaultTab;
  /** View mode selected in the unified resource view (Cards/List). */
  viewMode: ViewMode;
  /** Labels view mode is whether the labels for resources should all be collapsed or expanded. This only applies to the list view. */
  labelsViewMode: LabelsViewMode;
}

export enum DefaultTab {
  DEFAULT_TAB_UNSPECIFIED = 0,
  DEFAULT_TAB_ALL = 1,
  DEFAULT_TAB_PINNED = 2,
}

export enum ViewMode {
  VIEW_MODE_UNSPECIFIED = 0,
  VIEW_MODE_CARD = 1,
  VIEW_MODE_LIST = 2,
}

export enum LabelsViewMode {
  LABELS_VIEW_MODE_UNSPECIFIED = 0,
  LABELS_VIEW_MODE_EXPANDED = 1,
  LABELS_VIEW_MODE_COLLAPSED = 2,
}