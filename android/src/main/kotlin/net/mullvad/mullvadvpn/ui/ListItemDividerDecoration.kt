package net.mullvad.mullvadvpn.ui

import android.graphics.Rect
import android.view.View
import androidx.recyclerview.widget.RecyclerView
import androidx.recyclerview.widget.RecyclerView.ItemDecoration
import androidx.recyclerview.widget.RecyclerView.State

class ListItemDividerDecoration(var bottomOffset: Int = 0, var topOffset: Int = 0) :
    ItemDecoration() {

    override fun getItemOffsets(offsets: Rect, view: View, parent: RecyclerView, state: State) {
        offsets.bottom = bottomOffset
        offsets.top = topOffset
    }
}
