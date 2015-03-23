package wsattacker.sso.openid.attacker.attack.parameter;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.jdesktop.observablecollections.ObservableCollections;
import org.jdesktop.observablecollections.ObservableList;
import wsattacker.sso.openid.attacker.attack.parameter.utilities.SearchReplaceHolder;

public class SearchReplaceAttackParameter extends AttackParameter {

    private List<SearchReplaceHolder> searchReplaceList;
    public static final String PROP_SEARCHREPLACELIST = "searchReplaceList";

    /**
     * Get the value of searchReplaceList
     *
     * @return the value of searchReplaceList
     */
    public List<SearchReplaceHolder> getSearchReplaceList() {
        return searchReplaceList;
    }

    /**
     * Set the value of searchReplaceList
     *
     * @param searchReplaceList new value of searchReplaceList
     */
    public void setSearchReplaceList(List<SearchReplaceHolder> searchReplaceList) {
        List<SearchReplaceHolder> oldSearchReplaceList = this.searchReplaceList;
        this.searchReplaceList = searchReplaceList;
        firePropertyChange(PROP_SEARCHREPLACELIST, oldSearchReplaceList, searchReplaceList);
    }

    public SearchReplaceAttackParameter() {
        super();
        List<SearchReplaceHolder> listToObserve = new ArrayList<>();
        ObservableList<SearchReplaceHolder> observableList = ObservableCollections.observableList(listToObserve);
        this.searchReplaceList = observableList;
    }

    @Override
    public String getAttackValue() {
        String result;
        if (!searchReplaceList.isEmpty()) {
            result = applySearchReplaceList();
        } else {
            result = super.getAttackValue();
        }
        return result;
    }

    private String applySearchReplaceList() {
        String result = super.getValidValue();
        for (SearchReplaceHolder srh : searchReplaceList) {
            String search = maybeUrlEncode(srh, srh.getSearch());
            String replace = maybeUrlEncode(srh, srh.getReplace());
            result = result.replace(search, replace);
        }
        return result;
    }

    private String maybeUrlEncode(SearchReplaceHolder srh, String toEncode) throws IllegalStateException {
        if (srh.isUrlEncode()) {
            try {
                toEncode = URLEncoder.encode(toEncode, "utf-8");
            } catch (UnsupportedEncodingException ex) {
                Logger.getLogger(getClass().getName()).log(Level.SEVERE, null, ex);
                throw new IllegalStateException("This should never happen", ex);
            }
        }
        return toEncode;
    }
}
